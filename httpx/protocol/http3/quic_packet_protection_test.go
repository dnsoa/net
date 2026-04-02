package http3

import (
	"bytes"
	"crypto/tls"
	"testing"
)

func TestQUICInitialPacketProtectionRoundTrip(t *testing.T) {
	dcid := bytes.Repeat([]byte{0xaa}, 8)
	scid := bytes.Repeat([]byte{0xbb}, 8)
	clientSecret, serverSecret, err := DeriveQUICInitialSecrets(dcid)
	if err != nil {
		t.Fatalf("derive initial secrets: %v", err)
	}
	plaintext, err := AppendQUICCryptoFrame(nil, 0, []byte("clienthello"))
	if err != nil {
		t.Fatalf("append crypto frame: %v", err)
	}
	packet, err := ProtectQUICPacket(QUICPacketHeader{
		Type:                    QUICPacketTypeInitial,
		IsLongHeader:            true,
		DestinationConnectionID: dcid,
		SourceConnectionID:      scid,
		PacketNumber:            7,
		PacketNumberLength:      4,
	}, plaintext, clientSecret, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("protect initial packet: %v", err)
	}
	header, decrypted, err := UnprotectQUICPacket(packet, DefaultShortHeaderDestinationConnectionIDLength, clientSecret, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("unprotect initial packet: %v", err)
	}
	if header.Type != QUICPacketTypeInitial || header.PacketNumber != 7 {
		t.Fatalf("unexpected initial header %+v", header)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("unexpected initial plaintext %x", decrypted)
	}
	serverPacket, err := ProtectQUICPacket(QUICPacketHeader{
		Type:                    QUICPacketTypeInitial,
		IsLongHeader:            true,
		DestinationConnectionID: scid,
		SourceConnectionID:      dcid,
		PacketNumber:            9,
		PacketNumberLength:      4,
	}, plaintext, serverSecret, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("protect server initial packet: %v", err)
	}
	if _, _, err := UnprotectQUICPacket(serverPacket, DefaultShortHeaderDestinationConnectionIDLength, serverSecret, tls.TLS_AES_128_GCM_SHA256); err != nil {
		t.Fatalf("unprotect server initial packet: %v", err)
	}
}

func TestQUICApplicationPacketProtectionRoundTripAES(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, 32)
	dcid := bytes.Repeat([]byte{0xcc}, DefaultShortHeaderDestinationConnectionIDLength)
	plaintext, err := AppendQUICAckFrame(nil, 0, []QUICAckRange{{Smallest: 3, Largest: 5}})
	if err != nil {
		t.Fatalf("append ack frame: %v", err)
	}
	packet, err := ProtectQUICPacket(QUICPacketHeader{
		Type:                    QUICPacketTypeOneRTT,
		IsLongHeader:            false,
		DestinationConnectionID: dcid,
		PacketNumber:            13,
		PacketNumberLength:      4,
	}, plaintext, secret, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("protect application packet: %v", err)
	}
	header, decrypted, err := UnprotectQUICPacket(packet, DefaultShortHeaderDestinationConnectionIDLength, secret, tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("unprotect application packet: %v", err)
	}
	if header.Type != QUICPacketTypeOneRTT || header.PacketNumber != 13 {
		t.Fatalf("unexpected application header %+v", header)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("unexpected application plaintext %x", decrypted)
	}
}
