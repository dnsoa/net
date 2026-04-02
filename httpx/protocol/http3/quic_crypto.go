package http3

import (
	"fmt"
	"io"
)

const quicFrameTypeCrypto byte = 0x06

type QUICCryptoFrame struct {
	Offset uint64
	Data   []byte
}

func AppendQUICCryptoFrame(dst []byte, offset uint64, data []byte) ([]byte, error) {
	dst = append(dst, quicFrameTypeCrypto)
	var err error
	dst, err = AppendVarInt(dst, offset)
	if err != nil {
		return nil, err
	}
	dst, err = AppendVarInt(dst, uint64(len(data)))
	if err != nil {
		return nil, err
	}
	dst = append(dst, data...)
	return dst, nil
}

func ParseQUICCryptoFrames(payload []byte) ([]QUICCryptoFrame, error) {
	frames := make([]QUICCryptoFrame, 0, 1)
	for offset := 0; offset < len(payload); {
		switch payload[offset] {
		case quicFrameTypePadding, quicFrameTypePing:
			offset++
			continue
		case quicFrameTypeAck, quicFrameTypeAckECN:
			_, consumed, err := ParseQUICAckFrame(payload[offset:])
			if err != nil {
				return nil, err
			}
			offset += consumed
		case quicFrameTypeConnectionClose, quicFrameTypeConnectionCloseApp:
			_, consumed, err := decodeConnectionCloseFrame(payload[offset:])
			if err != nil {
				return nil, err
			}
			offset += consumed
		case quicFrameTypeCrypto:
			frame, consumed, err := parseQUICCryptoFrame(payload[offset:])
			if err != nil {
				return nil, err
			}
			frames = append(frames, frame)
			offset += consumed
		default:
			return nil, fmt.Errorf("http3 unsupported quic handshake frame type 0x%x", payload[offset])
		}
	}
	return frames, nil
}

func parseQUICCryptoFrame(payload []byte) (QUICCryptoFrame, int, error) {
	if len(payload) == 0 || payload[0] != quicFrameTypeCrypto {
		return QUICCryptoFrame{}, 0, fmt.Errorf("http3 invalid crypto frame")
	}
	offset := 1
	cryptoOffset, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return QUICCryptoFrame{}, 0, err
	}
	offset += n
	cryptoLen, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return QUICCryptoFrame{}, 0, err
	}
	offset += n
	if len(payload[offset:]) < int(cryptoLen) {
		return QUICCryptoFrame{}, 0, io.ErrUnexpectedEOF
	}
	return QUICCryptoFrame{
		Offset: cryptoOffset,
		Data:   append([]byte(nil), payload[offset:offset+int(cryptoLen)]...),
	}, offset + int(cryptoLen), nil
}
