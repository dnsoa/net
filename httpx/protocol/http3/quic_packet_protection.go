package http3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"hash"
)

var quicInitialSaltV1 = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

type quicPacketProtectionKeys struct {
	aead      cipher.AEAD
	hp        cipher.Block
	iv        []byte
	sampleLen int
}

func DeriveQUICInitialSecrets(dcid []byte) ([]byte, []byte, error) {
	if len(dcid) == 0 {
		return nil, nil, fmt.Errorf("http3 quic initial dcid is required")
	}
	initialSecret, err := hkdf.Extract(sha256.New, dcid, quicInitialSaltV1)
	if err != nil {
		return nil, nil, err
	}
	clientSecret, err := quicHKDFExpandLabel(sha256.New, initialSecret, "client in", nil, sha256.Size)
	if err != nil {
		return nil, nil, err
	}
	serverSecret, err := quicHKDFExpandLabel(sha256.New, initialSecret, "server in", nil, sha256.Size)
	if err != nil {
		return nil, nil, err
	}
	return clientSecret, serverSecret, nil
}

func ProtectQUICPacket(header QUICPacketHeader, plaintext []byte, secret []byte, suite uint16) ([]byte, error) {
	keys, err := newQUICPacketProtectionKeys(secret, suite)
	if err != nil {
		return nil, err
	}
	pnLen := header.PacketNumberLength
	if pnLen <= 0 || pnLen > 4 {
		pnLen = 4
	}
	packet, pnOffset, err := encodeQUICPacketHeaderForProtection(header, pnLen, len(plaintext)+keys.aead.Overhead())
	if err != nil {
		return nil, err
	}
	aad := append([]byte(nil), packet...)
	nonce := quicPacketNonce(keys.iv, header.PacketNumber)
	ciphertext := keys.aead.Seal(nil, nonce, plaintext, aad)
	packet = append(packet, ciphertext...)
	if len(packet) < pnOffset+4+keys.sampleLen {
		return nil, fmt.Errorf("http3 quic packet too short for header protection")
	}
	sample := packet[pnOffset+4 : pnOffset+4+keys.sampleLen]
	mask, err := quicHeaderProtectionMask(keys.hp, sample)
	if err != nil {
		return nil, err
	}
	if header.IsLongHeader {
		packet[0] ^= mask[0] & 0x0f
	} else {
		packet[0] ^= mask[0] & 0x1f
	}
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[i+1]
	}
	return packet, nil
}

func UnprotectQUICPacket(packet []byte, shortHeaderDestinationConnectionIDLength int, secret []byte, suite uint16) (QUICPacketHeader, []byte, error) {
	keys, err := newQUICPacketProtectionKeys(secret, suite)
	if err != nil {
		return QUICPacketHeader{}, nil, err
	}
	decoded := append([]byte(nil), packet...)
	pnOffset, isLongHeader, err := quicPacketNumberOffset(decoded, shortHeaderDestinationConnectionIDLength)
	if err != nil {
		return QUICPacketHeader{}, nil, err
	}
	if len(decoded) < pnOffset+4+keys.sampleLen {
		return QUICPacketHeader{}, nil, fmt.Errorf("http3 quic packet too short for header protection")
	}
	sample := decoded[pnOffset+4 : pnOffset+4+keys.sampleLen]
	mask, err := quicHeaderProtectionMask(keys.hp, sample)
	if err != nil {
		return QUICPacketHeader{}, nil, err
	}
	if isLongHeader {
		decoded[0] ^= mask[0] & 0x0f
	} else {
		decoded[0] ^= mask[0] & 0x1f
	}
	pnLen := int(decoded[0]&0x03) + 1
	if len(decoded) < pnOffset+pnLen {
		return QUICPacketHeader{}, nil, ioUnexpectedEOF()
	}
	for i := 0; i < pnLen; i++ {
		decoded[pnOffset+i] ^= mask[i+1]
	}
	header, err := ParseQUICPacketHeader(decoded, shortHeaderDestinationConnectionIDLength)
	if err != nil {
		return QUICPacketHeader{}, nil, err
	}
	if header.PayloadOffset > len(decoded) {
		return QUICPacketHeader{}, nil, ioUnexpectedEOF()
	}
	ciphertextEnd := len(decoded)
	if header.IsLongHeader {
		ciphertextLen := int(header.Length) - header.PacketNumberLength
		if ciphertextLen < 0 {
			return QUICPacketHeader{}, nil, ioUnexpectedEOF()
		}
		ciphertextEnd = header.PayloadOffset + ciphertextLen
		if ciphertextEnd > len(decoded) {
			return QUICPacketHeader{}, nil, ioUnexpectedEOF()
		}
	}
	nonce := quicPacketNonce(keys.iv, header.PacketNumber)
	plaintext, err := keys.aead.Open(nil, nonce, decoded[header.PayloadOffset:ciphertextEnd], decoded[:header.PayloadOffset])
	if err != nil {
		return QUICPacketHeader{}, nil, err
	}
	return header, plaintext, nil
}

func newQUICPacketProtectionKeys(secret []byte, suite uint16) (*quicPacketProtectionKeys, error) {
	hashFunc, keyLen, err := quicProtectionSuiteParams(suite)
	if err != nil {
		return nil, err
	}
	key, err := quicHKDFExpandLabel(hashFunc, secret, "quic key", nil, keyLen)
	if err != nil {
		return nil, err
	}
	iv, err := quicHKDFExpandLabel(hashFunc, secret, "quic iv", nil, 12)
	if err != nil {
		return nil, err
	}
	hpKey, err := quicHKDFExpandLabel(hashFunc, secret, "quic hp", nil, keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	aeadBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(aeadBlock)
	if err != nil {
		return nil, err
	}
	return &quicPacketProtectionKeys{aead: aead, hp: block, iv: iv, sampleLen: 16}, nil
}

func quicProtectionSuiteParams(suite uint16) (func() hash.Hash, int, error) {
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
		return sha256.New, 16, nil
	case tls.TLS_AES_256_GCM_SHA384:
		return sha512.New384, 32, nil
	default:
		return nil, 0, fmt.Errorf("http3 unsupported quic protection cipher suite 0x%x", suite)
	}
}

func quicHKDFExpandLabel(hashFunc func() hash.Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := append([]byte("tls13 "), []byte(label)...)
	info := make([]byte, 0, 3+len(fullLabel)+len(context))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdf.Expand(hashFunc, secret, string(info), length)
}

func quicPacketNonce(iv []byte, packetNumber uint64) []byte {
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8 && i < len(nonce); i++ {
		nonce[len(nonce)-1-i] ^= byte(packetNumber >> (8 * i))
	}
	return nonce
}

func quicHeaderProtectionMask(block cipher.Block, sample []byte) ([]byte, error) {
	if block == nil {
		return nil, fmt.Errorf("http3 quic header protection block is not configured")
	}
	if len(sample) < block.BlockSize() {
		return nil, fmt.Errorf("http3 quic sample too short for header protection")
	}
	mask := make([]byte, block.BlockSize())
	block.Encrypt(mask, sample[:block.BlockSize()])
	return mask[:5], nil
}

func quicPacketNumberOffset(packet []byte, shortHeaderDestinationConnectionIDLength int) (int, bool, error) {
	if len(packet) == 0 {
		return 0, false, ioUnexpectedEOF()
	}
	first := packet[0]
	if first&0x40 == 0 {
		return 0, false, ErrNotQUICPacket
	}
	if first&0x80 == 0 {
		offset := 1 + shortHeaderDestinationConnectionIDLength
		if len(packet) < offset+4 {
			return 0, false, ioUnexpectedEOF()
		}
		return offset, false, nil
	}
	if len(packet) < 6 {
		return 0, true, ioUnexpectedEOF()
	}
	offset := 5
	dcidLen := int(packet[offset])
	offset++
	if len(packet) < offset+dcidLen+1 {
		return 0, true, ioUnexpectedEOF()
	}
	offset += dcidLen
	scidLen := int(packet[offset])
	offset++
	if len(packet) < offset+scidLen {
		return 0, true, ioUnexpectedEOF()
	}
	offset += scidLen
	packetType := QUICPacketType((first >> 4) & 0x03)
	if packetType == 0x00 {
		tokenLen, n, err := DecodeVarInt(packet[offset:])
		if err != nil {
			return 0, true, err
		}
		offset += n + int(tokenLen)
	}
	_, n, err := DecodeVarInt(packet[offset:])
	if err != nil {
		return 0, true, err
	}
	offset += n
	if len(packet) < offset+4 {
		return 0, true, ioUnexpectedEOF()
	}
	return offset, true, nil
}

func encodeQUICPacketHeaderForProtection(header QUICPacketHeader, packetNumberLength int, ciphertextLen int) ([]byte, int, error) {
	if packetNumberLength <= 0 || packetNumberLength > 4 {
		packetNumberLength = 4
	}
	if header.IsLongHeader {
		var firstByte byte
		switch header.Type {
		case QUICPacketTypeInitial:
			firstByte = 0xc0 | byte((packetNumberLength-1)&0x03)
		case QUICPacketTypeHandshake:
			firstByte = 0xe0 | byte((packetNumberLength-1)&0x03)
		default:
			return nil, 0, fmt.Errorf("http3 unsupported protected long-header packet type %s", header.Type)
		}
		packet := []byte{firstByte, 0x00, 0x00, 0x00, 0x01}
		packet = append(packet, byte(len(header.DestinationConnectionID)))
		packet = append(packet, header.DestinationConnectionID...)
		packet = append(packet, byte(len(header.SourceConnectionID)))
		packet = append(packet, header.SourceConnectionID...)
		var err error
		if header.Type == QUICPacketTypeInitial {
			packet, err = AppendVarInt(packet, header.TokenLength)
			if err != nil {
				return nil, 0, err
			}
		}
		packet, err = AppendVarInt(packet, uint64(packetNumberLength+ciphertextLen))
		if err != nil {
			return nil, 0, err
		}
		pnOffset := len(packet)
		packet = appendQUICProtectedPacketNumber(packet, header.PacketNumber, packetNumberLength)
		return packet, pnOffset, nil
	}
	packet := []byte{0x40 | byte((packetNumberLength-1)&0x03)}
	packet = append(packet, header.DestinationConnectionID...)
	pnOffset := len(packet)
	packet = appendQUICProtectedPacketNumber(packet, header.PacketNumber, packetNumberLength)
	return packet, pnOffset, nil
}

func appendQUICProtectedPacketNumber(dst []byte, packetNumber uint64, packetNumberLength int) []byte {
	for shift := (packetNumberLength - 1) * 8; shift >= 0; shift -= 8 {
		dst = append(dst, byte(packetNumber>>shift))
		if shift == 0 {
			break
		}
	}
	return dst
}
