package http3

import "errors"

type FrameType uint64

const (
	FrameData        FrameType = 0x00
	FrameHeaders     FrameType = 0x01
	FrameCancelPush  FrameType = 0x03
	FrameSettings    FrameType = 0x04
	FramePushPromise FrameType = 0x05
	FrameGoAway      FrameType = 0x07
	FrameMaxPushID   FrameType = 0x0d
)

type Settings struct {
	MaxFieldSectionSize uint64
	QPACKMaxTableCap    uint64
	QPACKBlockedStreams uint64
}

type ErrorCode uint64

const (
	ErrNoError              ErrorCode = 0x100
	ErrGeneralProtocolError ErrorCode = 0x101
	ErrInternalError        ErrorCode = 0x102
	ErrStreamCreationError  ErrorCode = 0x103
	ErrClosedCriticalStream ErrorCode = 0x104
	ErrFrameUnexpected      ErrorCode = 0x105
	ErrFrameError           ErrorCode = 0x106
	ErrExcessiveLoad        ErrorCode = 0x107
	ErrIDError              ErrorCode = 0x108
	ErrSettingsError        ErrorCode = 0x109
	ErrMissingSettings      ErrorCode = 0x10a
	ErrRequestRejected      ErrorCode = 0x10b
	ErrRequestCancelled     ErrorCode = 0x10c
	ErrRequestIncomplete    ErrorCode = 0x10d
	ErrMessageError         ErrorCode = 0x10e
	ErrConnectError         ErrorCode = 0x10f
	ErrVersionFallback      ErrorCode = 0x110
)

func AppendVarInt(dst []byte, value uint64) ([]byte, error) {
	switch {
	case value < 64:
		return append(dst, byte(value)), nil
	case value < 16384:
		return append(dst, byte((value>>8)|0x40), byte(value&0xFF)), nil
	case value < 1073741824:
		return append(dst, byte((value>>24)|0x80), byte((value>>16)&0xFF), byte((value>>8)&0xFF), byte(value&0xFF)), nil
	case value < 4611686018427387904:
		return append(dst,
			byte((value>>56)|0xC0), byte((value>>48)&0xFF), byte((value>>40)&0xFF), byte((value>>32)&0xFF),
			byte((value>>24)&0xFF), byte((value>>16)&0xFF), byte((value>>8)&0xFF), byte(value&0xFF),
		), nil
	default:
		return nil, errors.New("http3 varint too large")
	}
}

func DecodeVarInt(data []byte) (value uint64, n int, err error) {
	if len(data) == 0 {
		return 0, 0, errors.New("unexpected eof")
	}
	prefix := data[0] >> 6
	n = 1 << prefix
	if len(data) < n {
		return 0, 0, errors.New("unexpected eof")
	}
	value = uint64(data[0] & 0x3F)
	for i := 1; i < n; i++ {
		value = (value << 8) | uint64(data[i])
	}
	return value, n, nil
}

type FrameHeader struct {
	Type   uint64
	Length uint64
}

func (h FrameHeader) Encode(dst []byte) ([]byte, error) {
	var err error
	dst, err = AppendVarInt(dst, h.Type)
	if err != nil {
		return nil, err
	}
	dst, err = AppendVarInt(dst, h.Length)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func DecodeFrameHeader(data []byte) (FrameHeader, int, error) {
	frameType, n1, err := DecodeVarInt(data)
	if err != nil {
		return FrameHeader{}, 0, err
	}
	length, n2, err := DecodeVarInt(data[n1:])
	if err != nil {
		return FrameHeader{}, 0, err
	}
	return FrameHeader{Type: frameType, Length: length}, n1 + n2, nil
}
