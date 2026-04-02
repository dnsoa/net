package http3

import "strconv"

type ServerConnStreamType uint8

const (
	ServerConnStreamTypeUnknown ServerConnStreamType = iota
	ServerConnStreamTypeQUICInitial
	ServerConnStreamTypeQUICHandshake
	ServerConnStreamTypeQUIC1RTT
	ServerConnStreamTypeControl
	ServerConnStreamTypeQPACKEncoder
	ServerConnStreamTypeQPACKDecoder
	ServerConnStreamTypePush
	ServerConnStreamTypeRequest
)

func (s ServerConnStreamType) String() string {
	switch s {
	case ServerConnStreamTypeUnknown:
		return "unknown"
	case ServerConnStreamTypeQUICInitial:
		return "quic-initial"
	case ServerConnStreamTypeQUICHandshake:
		return "quic-handshake"
	case ServerConnStreamTypeQUIC1RTT:
		return "quic-1rtt"
	case ServerConnStreamTypeControl:
		return "control"
	case ServerConnStreamTypeQPACKEncoder:
		return "qpack-encoder"
	case ServerConnStreamTypeQPACKDecoder:
		return "qpack-decoder"
	case ServerConnStreamTypePush:
		return "push"
	case ServerConnStreamTypeRequest:
		return "request"
	default:
		return "ServerConnStreamType(" + strconv.FormatUint(uint64(s), 10) + ")"
	}
}

func (s ServerConnStreamType) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s ServerConnStreamType) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(s.String())), nil
}
