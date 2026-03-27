package http2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/dnsoa/net/httpx/core"
)

type NegotiatedProtocol uint8

const (
	NegotiatedHTTP10 NegotiatedProtocol = iota
	NegotiatedHTTP11
	NegotiatedHTTP2
	NegotiatedHTTP3
)

func (p NegotiatedProtocol) ToVersion() core.Version {
	switch p {
	case NegotiatedHTTP10:
		return core.VersionHTTP10
	case NegotiatedHTTP2:
		return core.VersionHTTP2
	case NegotiatedHTTP3:
		return core.VersionHTTP3
	default:
		return core.VersionHTTP11
	}
}

const (
	ALPNHTTP11 = "http/1.1"
	ALPNHTTP2  = "h2"
	ALPNHTTP3  = "h3"
	Preface    = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

func NegotiateVersion(alpn []byte) NegotiatedProtocol {
	switch string(alpn) {
	case ALPNHTTP3:
		return NegotiatedHTTP3
	case ALPNHTTP2:
		return NegotiatedHTTP2
	case ALPNHTTP11:
		return NegotiatedHTTP11
	default:
		return NegotiatedHTTP11
	}
}

func IsH2CUpgradeRequest(headers *core.Headers) bool {
	upgrade := headers.Get("Upgrade")
	if upgrade == nil || !bytes.EqualFold(upgrade, []byte("h2c")) {
		return false
	}
	connection := headers.Get("Connection")
	if connection == nil {
		return false
	}
	if !core.ContainsTokenCI(connection, []byte("Upgrade")) {
		return false
	}
	return headers.Get("HTTP2-Settings") != nil
}

type FrameType uint8

const (
	FrameData FrameType = iota
	FrameHeaders
	FramePriority
	FrameRSTStream
	FrameSettings
	FramePushPromise
	FramePing
	FrameGoAway
	FrameWindowUpdate
	FrameContinuation
)

const (
	FlagEndStream  uint8 = 0x1
	FlagAck        uint8 = 0x1
	FlagEndHeaders uint8 = 0x4
)

type FrameHeader struct {
	Length   uint32
	Type     FrameType
	Flags    uint8
	StreamID uint32
}

func (h FrameHeader) Serialize() [9]byte {
	var out [9]byte
	out[0] = byte((h.Length >> 16) & 0xFF)
	out[1] = byte((h.Length >> 8) & 0xFF)
	out[2] = byte(h.Length & 0xFF)
	out[3] = byte(h.Type)
	out[4] = h.Flags
	streamID := h.StreamID & 0x7fffffff
	out[5] = byte((streamID >> 24) & 0x7F)
	out[6] = byte((streamID >> 16) & 0xFF)
	out[7] = byte((streamID >> 8) & 0xFF)
	out[8] = byte(streamID & 0xFF)
	return out
}

func ParseFrameHeader(data [9]byte) FrameHeader {
	return FrameHeader{
		Length: uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2]),
		Type:   FrameType(data[3]),
		Flags:  data[4],
		StreamID: uint32(data[5]&0x7F)<<24 |
			uint32(data[6])<<16 |
			uint32(data[7])<<8 |
			uint32(data[8]),
	}
}

type SettingID uint16

const (
	SettingHeaderTableSize      SettingID = 0x1
	SettingEnablePush           SettingID = 0x2
	SettingMaxConcurrentStreams SettingID = 0x3
	SettingInitialWindowSize    SettingID = 0x4
	SettingMaxFrameSize         SettingID = 0x5
	SettingMaxHeaderListSize    SettingID = 0x6
)

type ErrorCode uint32

const (
	ErrNoError            ErrorCode = 0x0
	ErrProtocolError      ErrorCode = 0x1
	ErrInternalError      ErrorCode = 0x2
	ErrFlowControlError   ErrorCode = 0x3
	ErrSettingsTimeout    ErrorCode = 0x4
	ErrStreamClosed       ErrorCode = 0x5
	ErrFrameSizeError     ErrorCode = 0x6
	ErrRefusedStream      ErrorCode = 0x7
	ErrCancel             ErrorCode = 0x8
	ErrCompressionError   ErrorCode = 0x9
	ErrConnectError       ErrorCode = 0xa
	ErrEnhanceYourCalm    ErrorCode = 0xb
	ErrInadequateSecurity ErrorCode = 0xc
	ErrHTTP11Required     ErrorCode = 0xd
)

type ConnectionSettings struct {
	HeaderTableSize      uint32
	EnablePush           bool
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32
}

func DefaultConnectionSettings() ConnectionSettings {
	return ConnectionSettings{
		HeaderTableSize:      4096,
		EnablePush:           true,
		MaxConcurrentStreams: 100,
		InitialWindowSize:    65535,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    8192,
	}
}

func EncodeSettingsPayload(settings ConnectionSettings, dst []byte) []byte {
	dst = appendSetting(dst, SettingHeaderTableSize, settings.HeaderTableSize)
	push := uint32(0)
	if settings.EnablePush {
		push = 1
	}
	dst = appendSetting(dst, SettingEnablePush, push)
	dst = appendSetting(dst, SettingMaxConcurrentStreams, settings.MaxConcurrentStreams)
	dst = appendSetting(dst, SettingInitialWindowSize, settings.InitialWindowSize)
	dst = appendSetting(dst, SettingMaxFrameSize, settings.MaxFrameSize)
	dst = appendSetting(dst, SettingMaxHeaderListSize, settings.MaxHeaderListSize)
	return dst
}

func ApplySettingsPayload(settings *ConnectionSettings, payload []byte) error {
	if len(payload)%6 != 0 {
		return errors.New("invalid http2 settings payload")
	}
	for offset := 0; offset < len(payload); offset += 6 {
		id := SettingID(binary.BigEndian.Uint16(payload[offset : offset+2]))
		value := binary.BigEndian.Uint32(payload[offset+2 : offset+6])
		switch id {
		case SettingHeaderTableSize:
			settings.HeaderTableSize = value
		case SettingEnablePush:
			settings.EnablePush = value != 0
		case SettingMaxConcurrentStreams:
			settings.MaxConcurrentStreams = value
		case SettingInitialWindowSize:
			settings.InitialWindowSize = value
		case SettingMaxFrameSize:
			settings.MaxFrameSize = value
		case SettingMaxHeaderListSize:
			settings.MaxHeaderListSize = value
		}
	}
	return nil
}

type Frame struct {
	Header  FrameHeader
	Payload []byte
}

type Conn struct {
	reader       io.Reader
	writer       io.Writer
	NextStreamID uint32
	Settings     ConnectionSettings
	PeerSettings ConnectionSettings
	IsClient     bool
}

func NewConn(reader io.Reader, writer io.Writer) *Conn {
	defaults := DefaultConnectionSettings()
	return &Conn{
		reader:       reader,
		writer:       writer,
		NextStreamID: 1,
		Settings:     defaults,
		PeerSettings: defaults,
		IsClient:     true,
	}
}

func (c *Conn) Handshake() error {
	if c.writer == nil {
		return errors.New("http2 writer is nil")
	}
	if _, err := io.WriteString(c.writer, Preface); err != nil {
		return err
	}
	payload := EncodeSettingsPayload(c.Settings, nil)
	return c.WriteFrame(FrameHeader{Length: uint32(len(payload)), Type: FrameSettings, StreamID: 0}, payload)
}

func (c *Conn) ReadFrame(maxPayloadSize int) (Frame, error) {
	if c.reader == nil {
		return Frame{}, errors.New("http2 reader is nil")
	}
	var hdrBytes [9]byte
	if _, err := io.ReadFull(c.reader, hdrBytes[:]); err != nil {
		return Frame{}, err
	}
	header := ParseFrameHeader(hdrBytes)
	if maxPayloadSize > 0 && int(header.Length) > maxPayloadSize {
		return Frame{}, errors.New("http2 frame too large")
	}
	payload := make([]byte, header.Length)
	if header.Length > 0 {
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return Frame{}, err
		}
	}
	return Frame{Header: header, Payload: payload}, nil
}

func (c *Conn) WriteFrame(header FrameHeader, payload []byte) error {
	if c.writer == nil {
		return errors.New("http2 writer is nil")
	}
	serialized := header.Serialize()
	if _, err := c.writer.Write(serialized[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := c.writer.Write(payload)
	return err
}

func appendSetting(dst []byte, id SettingID, value uint32) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(id))
	dst = binary.BigEndian.AppendUint32(dst, value)
	return dst
}
