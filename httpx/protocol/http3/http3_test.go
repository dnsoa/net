package http3

import (
	"bytes"
	"testing"
)

func TestVarIntRoundTrip(t *testing.T) {
	values := []uint64{25, 15293, 494878333, 151288809941952652}
	for _, value := range values {
		encoded, err := AppendVarInt(nil, value)
		if err != nil {
			t.Fatalf("encode %d: %v", value, err)
		}
		decoded, n, err := DecodeVarInt(encoded)
		if err != nil {
			t.Fatalf("decode %d: %v", value, err)
		}
		if decoded != value || n != len(encoded) {
			t.Fatalf("roundtrip mismatch value=%d decoded=%d n=%d encoded=%v", value, decoded, n, encoded)
		}
	}
}

func TestFrameHeaderRoundTrip(t *testing.T) {
	header := FrameHeader{Type: uint64(FrameHeaders), Length: 1234}
	encoded, err := header.Encode(nil)
	if err != nil {
		t.Fatalf("encode frame header: %v", err)
	}
	decoded, n, err := DecodeFrameHeader(encoded)
	if err != nil {
		t.Fatalf("decode frame header: %v", err)
	}
	if decoded != header || n != len(encoded) {
		t.Fatalf("frame header mismatch got=%+v n=%d want=%+v len=%d", decoded, n, header, len(encoded))
	}
}

func buildTestQUICInitialPacket(t *testing.T, dcid, scid, payload []byte) []byte {
	t.Helper()
	packet := []byte{0xc0}
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
	packet, err = AppendVarInt(packet, uint64(1+len(payload)))
	if err != nil {
		t.Fatalf("append payload length: %v", err)
	}
	packet = append(packet, 0x00)
	packet = append(packet, payload...)
	return packet
}

func buildTestQUICHandshakePacket(t *testing.T, dcid, scid, payload []byte) []byte {
	t.Helper()
	packet := []byte{0xe0}
	packet = append(packet, 0x00, 0x00, 0x00, 0x01)
	packet = append(packet, byte(len(dcid)))
	packet = append(packet, dcid...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)
	var err error
	packet, err = AppendVarInt(packet, uint64(1+len(payload)))
	if err != nil {
		t.Fatalf("append payload length: %v", err)
	}
	packet = append(packet, 0x00)
	packet = append(packet, payload...)
	return packet
}

func buildTestQUIC1RTTPacket(dcid, payload []byte) []byte {
	packet := []byte{0x40}
	packet = append(packet, dcid...)
	packet = append(packet, 0x00)
	packet = append(packet, payload...)
	return packet
}

func TestParseQUICPacketHeaderInitial(t *testing.T) {
	dcid := bytes.Repeat([]byte{0xaa}, 8)
	scid := bytes.Repeat([]byte{0xbb}, 8)
	packet := buildTestQUICInitialPacket(t, dcid, scid, []byte{0x01, 0x02})
	header, err := ParseQUICPacketHeader(packet, DefaultShortHeaderDestinationConnectionIDLength)
	if err != nil {
		t.Fatalf("parse initial packet header: %v", err)
	}
	if header.Type != QUICPacketTypeInitial {
		t.Fatalf("unexpected packet type %q", header.Type)
	}
	if !bytes.Equal(header.DestinationConnectionID, dcid) {
		t.Fatalf("unexpected dcid %x", header.DestinationConnectionID)
	}
	if !bytes.Equal(header.SourceConnectionID, scid) {
		t.Fatalf("unexpected scid %x", header.SourceConnectionID)
	}
	if header.PayloadOffset <= 0 || header.PayloadOffset > len(packet) {
		t.Fatalf("unexpected payload offset %d", header.PayloadOffset)
	}
}

func TestParseQUICPacketHeaderOneRTT(t *testing.T) {
	dcid := bytes.Repeat([]byte{0xcc}, DefaultShortHeaderDestinationConnectionIDLength)
	payload := []byte{0x08, 0x00}
	packet := buildTestQUIC1RTTPacket(dcid, payload)
	header, err := ParseQUICPacketHeader(packet, DefaultShortHeaderDestinationConnectionIDLength)
	if err != nil {
		t.Fatalf("parse 1-rtt packet header: %v", err)
	}
	if header.Type != QUICPacketTypeOneRTT {
		t.Fatalf("unexpected packet type %q", header.Type)
	}
	if !bytes.Equal(header.DestinationConnectionID, dcid) {
		t.Fatalf("unexpected dcid %x", header.DestinationConnectionID)
	}
	if header.PayloadOffset != 1+len(dcid)+1 {
		t.Fatalf("unexpected payload offset %d", header.PayloadOffset)
	}
}
