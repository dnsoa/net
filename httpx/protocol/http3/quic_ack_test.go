package http3

import (
	"bytes"
	"context"
	"testing"
)

func buildTestQUICInitialPacketWithPN(t *testing.T, dcid, scid []byte, packetNumber uint64, packetNumberLength int, payload []byte) []byte {
	t.Helper()
	packet := []byte{0xc0 | byte((packetNumberLength-1)&0x03)}
	packet = append(packet, 0x00, 0x00, 0x00, 0x01)
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)
	var err error
	packet, err = AppendVarInt(packet, 0)
	if err != nil {
		t.Fatalf("append token length: %v", err)
	}
	packet, err = AppendVarInt(packet, uint64(packetNumberLength+len(payload)))
	if err != nil {
		t.Fatalf("append payload length: %v", err)
	}
	packet = appendTruncatedPacketNumber(packet, packetNumber, packetNumberLength)
	packet = append(packet, payload...)
	return packet
}

func buildTestQUICHandshakePacketWithPN(t *testing.T, dcid, scid []byte, packetNumber uint64, packetNumberLength int, payload []byte) []byte {
	t.Helper()
	packet := []byte{0xe0 | byte((packetNumberLength-1)&0x03)}
	packet = append(packet, 0x00, 0x00, 0x00, 0x01)
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)
	var err error
	packet, err = AppendVarInt(packet, uint64(packetNumberLength+len(payload)))
	if err != nil {
		t.Fatalf("append payload length: %v", err)
	}
	packet = appendTruncatedPacketNumber(packet, packetNumber, packetNumberLength)
	packet = append(packet, payload...)
	return packet
}

func buildTestQUIC1RTTPacketWithPN(dcid []byte, packetNumber uint64, packetNumberLength int, payload []byte) []byte {
	packet := []byte{0x40 | byte((packetNumberLength-1)&0x03)}
	packet = append(packet, dcid...)
	packet = appendTruncatedPacketNumber(packet, packetNumber, packetNumberLength)
	packet = append(packet, payload...)
	return packet
}

func appendTruncatedPacketNumber(dst []byte, packetNumber uint64, packetNumberLength int) []byte {
	for shift := (packetNumberLength - 1) * 8; shift >= 0; shift -= 8 {
		dst = append(dst, byte(packetNumber>>shift))
		if shift == 0 {
			break
		}
	}
	return dst
}

func TestQUICAckFrameRoundTrip(t *testing.T) {
	ranges := []QUICAckRange{
		{Smallest: 100, Largest: 110},
		{Smallest: 90, Largest: 95},
		{Smallest: 88, Largest: 88},
	}
	encoded, err := AppendQUICAckFrame(nil, 7, ranges)
	if err != nil {
		t.Fatalf("append ack frame: %v", err)
	}
	decoded, consumed, err := ParseQUICAckFrame(encoded)
	if err != nil {
		t.Fatalf("parse ack frame: %v", err)
	}
	if consumed != len(encoded) {
		t.Fatalf("unexpected consumed length %d want %d", consumed, len(encoded))
	}
	if decoded.LargestAcknowledged != 110 {
		t.Fatalf("unexpected largest acknowledged %d", decoded.LargestAcknowledged)
	}
	if decoded.AckDelay != 7 {
		t.Fatalf("unexpected ack delay %d", decoded.AckDelay)
	}
	if len(decoded.Ranges) != len(ranges) {
		t.Fatalf("unexpected range count %d", len(decoded.Ranges))
	}
	for i := range ranges {
		if decoded.Ranges[i] != ranges[i] {
			t.Fatalf("unexpected range %d got %+v want %+v", i, decoded.Ranges[i], ranges[i])
		}
	}
}

func TestServerConnTracksPacketNumberSpacesAndACKs(t *testing.T) {
	conn := NewServerConn(NewServerSession(), NewMemoryStreamOpenerFactory().NewStreamOpener())
	dcid := bytes.Repeat([]byte{0xaa}, DefaultShortHeaderDestinationConnectionIDLength)
	scid := bytes.Repeat([]byte{0xbb}, 8)
	cryptoPayload, err := AppendQUICCryptoFrame(nil, 0, []byte("clienthello"))
	if err != nil {
		t.Fatalf("append crypto frame: %v", err)
	}
	if _, err := conn.HandlePacket(context.Background(), buildTestQUICInitialPacketWithPN(t, dcid, scid, 1, 1, cryptoPayload), nil); err != nil {
		t.Fatalf("handle initial packet: %v", err)
	}
	ackFrame, err := conn.DrainPendingAckFrame(QUICPacketNumberSpaceInitial)
	if err != nil {
		t.Fatalf("drain initial ack frame: %v", err)
	}
	decodedAck, _, err := ParseQUICAckFrame(ackFrame)
	if err != nil {
		t.Fatalf("parse drained ack frame: %v", err)
	}
	if len(decodedAck.Ranges) != 1 || decodedAck.Ranges[0] != (QUICAckRange{Smallest: 1, Largest: 1}) {
		t.Fatalf("unexpected initial ack ranges %+v", decodedAck.Ranges)
	}

	handshakePayload, err := AppendQUICCryptoFrame(nil, 0, []byte("serverhello"))
	if err != nil {
		t.Fatalf("append handshake crypto frame: %v", err)
	}
	if _, err := conn.HandlePacket(context.Background(), buildTestQUICHandshakePacketWithPN(t, dcid, scid, 3, 1, handshakePayload), nil); err != nil {
		t.Fatalf("handle handshake packet: %v", err)
	}

	peerAck, err := AppendQUICAckFrame(nil, 0, []QUICAckRange{{Smallest: 5, Largest: 7}})
	if err != nil {
		t.Fatalf("append peer ack frame: %v", err)
	}
	if _, err := conn.HandlePacket(context.Background(), buildTestQUIC1RTTPacketWithPN(dcid, 9, 1, peerAck), nil); err != nil {
		t.Fatalf("handle 1-rtt ack packet: %v", err)
	}

	snapshot := conn.Snapshot()
	if snapshot.InitialPacketSpace.ReceivedPackets != 1 || snapshot.InitialPacketSpace.LargestReceived != 1 {
		t.Fatalf("unexpected initial packet space snapshot %+v", snapshot.InitialPacketSpace)
	}
	if snapshot.InitialPacketSpace.PendingAck {
		t.Fatalf("expected initial packet space ack to be drained, got %+v", snapshot.InitialPacketSpace)
	}
	if snapshot.HandshakePacketSpace.ReceivedPackets != 1 || snapshot.HandshakePacketSpace.LargestReceived != 3 {
		t.Fatalf("unexpected handshake packet space snapshot %+v", snapshot.HandshakePacketSpace)
	}
	if snapshot.ApplicationPacketSpace.ReceivedPackets != 1 {
		t.Fatalf("unexpected application packet count %+v", snapshot.ApplicationPacketSpace)
	}
	if snapshot.ApplicationPacketSpace.LargestReceived != 9 {
		t.Fatalf("unexpected application largest packet number %+v", snapshot.ApplicationPacketSpace)
	}
	if snapshot.ApplicationPacketSpace.AckFramesSeen != 1 || snapshot.ApplicationPacketSpace.LargestAcked != 7 {
		t.Fatalf("unexpected application ack tracking %+v", snapshot.ApplicationPacketSpace)
	}
}

func TestServerConnExpandsPacketNumbersPerSpace(t *testing.T) {
	conn := NewServerConn(NewServerSession(), NewMemoryStreamOpenerFactory().NewStreamOpener())
	dcid := bytes.Repeat([]byte{0xaa}, DefaultShortHeaderDestinationConnectionIDLength)
	scid := bytes.Repeat([]byte{0xbb}, 8)
	cryptoPayload, err := AppendQUICCryptoFrame(nil, 0, []byte("x"))
	if err != nil {
		t.Fatalf("append crypto frame: %v", err)
	}
	if _, err := conn.HandlePacket(context.Background(), buildTestQUICInitialPacketWithPN(t, dcid, scid, 0xff, 1, cryptoPayload), nil); err != nil {
		t.Fatalf("handle first initial packet: %v", err)
	}
	if _, err := conn.HandlePacket(context.Background(), buildTestQUICInitialPacketWithPN(t, dcid, scid, 0x00, 1, cryptoPayload), nil); err != nil {
		t.Fatalf("handle second initial packet: %v", err)
	}
	snapshot := conn.Snapshot()
	if snapshot.InitialPacketSpace.LargestReceived != 0x100 {
		t.Fatalf("expected expanded packet number 256, got %+v", snapshot.InitialPacketSpace)
	}
}
