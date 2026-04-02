package http3

import "strconv"

type ServerConnMachineStep uint8

const (
	ServerConnMachineStepUnknown ServerConnMachineStep = iota
	ServerConnMachineStepQUICInitial
	ServerConnMachineStepQUICHandshake
	ServerConnMachineStepQUIC1RTT
	ServerConnMachineStepRequestStreamPending
	ServerConnMachineStepApplicationPacketIgnored
	ServerConnMachineStepStreamTypePending
	ServerConnMachineStepPushStreamUnsupported
	ServerConnMachineStepIgnoredUnknownStream
	ServerConnMachineStepUnknownStreamKind
	ServerConnMachineStepNonControlStream
	ServerConnMachineStepControlStreamPending
	ServerConnMachineStepControlStream
	ServerConnMachineStepUnexpectedControlFrame
	ServerConnMachineStepReservedControlFrame
	ServerConnMachineStepNonQPACKEncoderStream
	ServerConnMachineStepNonQPACKDecoderStream
	ServerConnMachineStepQPACKEncoderStream
	ServerConnMachineStepQPACKDecoderStream
	ServerConnMachineStepNonRequestStream
	ServerConnMachineStepRequestStreamIgnored
	ServerConnMachineStepRequestStreamActive
	ServerConnMachineStepRequestStreamIncomplete
	ServerConnMachineStepRequestStreamBadRequest
	ServerConnMachineStepRequestStreamResponse
	ServerConnMachineStepDuplicateCriticalStream
	ServerConnMachineStepCriticalStreamClosed
	ServerConnMachineStepGoAwayIDInvalidType
	ServerConnMachineStepGoAwayIDIncreased
	ServerConnMachineStepMaxPushIDDecreased
	ServerConnMachineStepCancelPushIDExceedsLimit
	ServerConnMachineStepCancelPushWithoutPromise
	ServerConnMachineStepRequestStreamReset
	ServerConnMachineStepRequestStreamStopSending
	ServerConnMachineStepConnectionClose
)

func (s ServerConnMachineStep) String() string {
	switch s {
	case ServerConnMachineStepUnknown:
		return "unknown"
	case ServerConnMachineStepQUICInitial:
		return "quic-initial"
	case ServerConnMachineStepQUICHandshake:
		return "quic-handshake"
	case ServerConnMachineStepQUIC1RTT:
		return "quic-1rtt"
	case ServerConnMachineStepRequestStreamPending:
		return "request-stream-pending"
	case ServerConnMachineStepApplicationPacketIgnored:
		return "application-packet-ignored"
	case ServerConnMachineStepStreamTypePending:
		return "stream-type-pending"
	case ServerConnMachineStepPushStreamUnsupported:
		return "push-stream-unsupported"
	case ServerConnMachineStepIgnoredUnknownStream:
		return "ignored-unknown-stream"
	case ServerConnMachineStepUnknownStreamKind:
		return "unknown-stream-kind"
	case ServerConnMachineStepNonControlStream:
		return "non-control-stream"
	case ServerConnMachineStepControlStreamPending:
		return "control-stream-pending"
	case ServerConnMachineStepControlStream:
		return "control-stream"
	case ServerConnMachineStepUnexpectedControlFrame:
		return "unexpected-control-frame"
	case ServerConnMachineStepReservedControlFrame:
		return "reserved-control-frame"
	case ServerConnMachineStepNonQPACKEncoderStream:
		return "non-qpack-encoder-stream"
	case ServerConnMachineStepNonQPACKDecoderStream:
		return "non-qpack-decoder-stream"
	case ServerConnMachineStepQPACKEncoderStream:
		return "qpack-encoder-stream"
	case ServerConnMachineStepQPACKDecoderStream:
		return "qpack-decoder-stream"
	case ServerConnMachineStepNonRequestStream:
		return "non-request-stream"
	case ServerConnMachineStepRequestStreamIgnored:
		return "request-stream-ignored"
	case ServerConnMachineStepRequestStreamActive:
		return "request-stream-active"
	case ServerConnMachineStepRequestStreamIncomplete:
		return "request-stream-incomplete"
	case ServerConnMachineStepRequestStreamBadRequest:
		return "request-stream-bad-request"
	case ServerConnMachineStepRequestStreamResponse:
		return "request-stream-response"
	case ServerConnMachineStepDuplicateCriticalStream:
		return "duplicate-critical-stream"
	case ServerConnMachineStepCriticalStreamClosed:
		return "critical-stream-closed"
	case ServerConnMachineStepGoAwayIDInvalidType:
		return "goaway-id-invalid-type"
	case ServerConnMachineStepGoAwayIDIncreased:
		return "goaway-id-increased"
	case ServerConnMachineStepMaxPushIDDecreased:
		return "max-push-id-decreased"
	case ServerConnMachineStepCancelPushIDExceedsLimit:
		return "cancel-push-id-exceeds-limit"
	case ServerConnMachineStepCancelPushWithoutPromise:
		return "cancel-push-without-promise"
	case ServerConnMachineStepRequestStreamReset:
		return "request-stream-reset"
	case ServerConnMachineStepRequestStreamStopSending:
		return "request-stream-stop-sending"
	case ServerConnMachineStepConnectionClose:
		return "connection-close"
	default:
		return "ServerConnMachineStep(" + strconv.FormatUint(uint64(s), 10) + ")"
	}
}

func (s ServerConnMachineStep) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s ServerConnMachineStep) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(s.String())), nil
}
