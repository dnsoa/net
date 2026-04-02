package http3

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var ErrNotQUICPacket = errors.New("http3 not a quic packet")

const DefaultShortHeaderDestinationConnectionIDLength = 8

type QUICPacketType uint8

const (
	QUICPacketTypeUnknown QUICPacketType = iota
	QUICPacketTypeInitial
	QUICPacketTypeZeroRTT
	QUICPacketTypeHandshake
	QUICPacketTypeRetry
	QUICPacketTypeVersionNegotiation
	QUICPacketTypeOneRTT
)

func (t QUICPacketType) String() string {
	switch t {
	case QUICPacketTypeInitial:
		return "initial"
	case QUICPacketTypeZeroRTT:
		return "0-rtt"
	case QUICPacketTypeHandshake:
		return "handshake"
	case QUICPacketTypeRetry:
		return "retry"
	case QUICPacketTypeVersionNegotiation:
		return "version-negotiation"
	case QUICPacketTypeOneRTT:
		return "1-rtt"
	default:
		return "unknown"
	}
}

type QUICPacketHeader struct {
	Type                    QUICPacketType
	IsLongHeader            bool
	Version                 uint32
	DestinationConnectionID []byte
	SourceConnectionID      []byte
	TokenLength             uint64
	PacketNumberLength      int
	PacketNumber            uint64
	PayloadOffset           int
}

func ParseQUICPacketHeader(packet []byte, shortHeaderDestinationConnectionIDLength int) (QUICPacketHeader, error) {
	if len(packet) == 0 {
		return QUICPacketHeader{}, ioUnexpectedEOF()
	}
	first := packet[0]
	if first&0x40 == 0 {
		return QUICPacketHeader{}, ErrNotQUICPacket
	}
	if first&0x80 != 0 {
		return parseLongHeaderPacket(packet, first)
	}
	return parseShortHeaderPacket(packet, first, shortHeaderDestinationConnectionIDLength)
}

func parseLongHeaderPacket(packet []byte, first byte) (QUICPacketHeader, error) {
	if len(packet) < 6 {
		return QUICPacketHeader{}, ioUnexpectedEOF()
	}
	header := QUICPacketHeader{IsLongHeader: true, Version: binary.BigEndian.Uint32(packet[1:5])}
	offset := 5
	dcidLen := int(packet[offset])
	offset++
	if len(packet) < offset+dcidLen+1 {
		return QUICPacketHeader{}, ioUnexpectedEOF()
	}
	header.DestinationConnectionID = append([]byte(nil), packet[offset:offset+dcidLen]...)
	offset += dcidLen
	scidLen := int(packet[offset])
	offset++
	if len(packet) < offset+scidLen {
		return QUICPacketHeader{}, ioUnexpectedEOF()
	}
	header.SourceConnectionID = append([]byte(nil), packet[offset:offset+scidLen]...)
	offset += scidLen
	if header.Version == 0 {
		header.Type = QUICPacketTypeVersionNegotiation
		header.PayloadOffset = offset
		return header, nil
	}
	header.PacketNumberLength = int(first&0x03) + 1
	switch (first >> 4) & 0x03 {
	case 0x00:
		header.Type = QUICPacketTypeInitial
		tokenLen, n, err := DecodeVarInt(packet[offset:])
		if err != nil {
			return QUICPacketHeader{}, err
		}
		header.TokenLength = tokenLen
		offset += n
		if len(packet) < offset+int(tokenLen) {
			return QUICPacketHeader{}, ioUnexpectedEOF()
		}
		offset += int(tokenLen)
	case 0x01:
		header.Type = QUICPacketTypeZeroRTT
	case 0x02:
		header.Type = QUICPacketTypeHandshake
	case 0x03:
		header.Type = QUICPacketTypeRetry
		header.PayloadOffset = offset
		return header, nil
	default:
		return QUICPacketHeader{}, fmt.Errorf("http3 unknown quic long-header packet type 0x%x", (first>>4)&0x03)
	}
	_, n, err := DecodeVarInt(packet[offset:])
	if err != nil {
		return QUICPacketHeader{}, err
	}
	offset += n
	if len(packet) < offset+header.PacketNumberLength {
		return QUICPacketHeader{}, ioUnexpectedEOF()
	}
	header.PacketNumber = decodeQUICPacketNumber(packet[offset : offset+header.PacketNumberLength])
	header.PayloadOffset = offset + header.PacketNumberLength
	return header, nil
}

func parseShortHeaderPacket(packet []byte, first byte, shortHeaderDestinationConnectionIDLength int) (QUICPacketHeader, error) {
	if shortHeaderDestinationConnectionIDLength < 0 {
		return QUICPacketHeader{}, ErrNotQUICPacket
	}
	header := QUICPacketHeader{
		Type:               QUICPacketTypeOneRTT,
		IsLongHeader:       false,
		PacketNumberLength: int(first&0x03) + 1,
	}
	offset := 1
	if len(packet) < offset+shortHeaderDestinationConnectionIDLength+header.PacketNumberLength {
		return QUICPacketHeader{}, ioUnexpectedEOF()
	}
	header.DestinationConnectionID = append([]byte(nil), packet[offset:offset+shortHeaderDestinationConnectionIDLength]...)
	offset += shortHeaderDestinationConnectionIDLength
	header.PacketNumber = decodeQUICPacketNumber(packet[offset : offset+header.PacketNumberLength])
	header.PayloadOffset = offset + header.PacketNumberLength
	return header, nil
}

func decodeQUICPacketNumber(packetNumber []byte) uint64 {
	var value uint64
	for _, b := range packetNumber {
		value = (value << 8) | uint64(b)
	}
	return value
}

func ioUnexpectedEOF() error {
	return errors.New("unexpected eof")
}
