package http3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dnsoa/go/allocator"
	"github.com/dnsoa/net/httpx/core"
)

const implicitRequestStreamID uint64 = 0

const (
	quicStreamFrameTypeBase         byte = 0x08
	quicStreamFrameTypeMax          byte = 0x0f
	quicFrameTypePadding            byte = 0x00
	quicFrameTypePing               byte = 0x01
	quicFrameTypeResetStream        byte = 0x04
	quicFrameTypeStopSending        byte = 0x05
	quicFrameTypeMaxStreamsBidi     byte = 0x12
	quicFrameTypeMaxStreamsUni      byte = 0x13
	quicFrameTypeNewConnectionID    byte = 0x18
	quicFrameTypeRetireConnectionID byte = 0x19
	quicFrameTypePathChallenge      byte = 0x1a
	quicFrameTypePathResponse       byte = 0x1b
	quicFrameTypeConnectionClose    byte = 0x1c
	quicFrameTypeConnectionCloseApp byte = 0x1d
	quicFrameTypeHandshakeDone      byte = 0x1e
	quicFrameTypeNewToken           byte = 0x07
	quicFrameTypeStreamsBlockedBidi byte = 0x16
	quicFrameTypeStreamsBlockedUni  byte = 0x17
)

type PeerStreamKind string

const (
	PeerStreamKindUnknown      PeerStreamKind = "unknown"
	PeerStreamKindControl      PeerStreamKind = "control"
	PeerStreamKindQPACKEncoder PeerStreamKind = "qpack-encoder"
	PeerStreamKindQPACKDecoder PeerStreamKind = "qpack-decoder"
	PeerStreamKindPush         PeerStreamKind = "push"
	PeerStreamKindIgnored      PeerStreamKind = "ignored"
	PeerStreamKindRequest      PeerStreamKind = "request"
)

type ServerRequestHandler interface {
	HandleRequest(context.Context, *core.Request) (*core.Response, error)
}

type ServerRequestHandlerFunc func(context.Context, *core.Request) (*core.Response, error)

func (f ServerRequestHandlerFunc) HandleRequest(ctx context.Context, req *core.Request) (*core.Response, error) {
	if f == nil {
		return nil, errors.New("http3 request handler is nil")
	}
	return f(ctx, req)
}

type ServerConnSnapshot struct {
	LastMachineStep        ServerConnMachineStep
	LastStreamType         ServerConnStreamType
	LastControlStreamID    uint64
	LastEncoderStreamID    uint64
	LastDecoderStreamID    uint64
	LastControlFrame       FrameType
	LastGoAwayID           uint64
	LastMaxPushID          uint64
	LastCancelPushID       uint64
	LastRequestStreamID    uint64
	LastRequestMethod      string
	LastRequestPath        string
	LastResponseStatus     int
	InitialPackets         uint64
	HandshakePackets       uint64
	OneRTTPackets          uint64
	ApplicationPackets     uint64
	ControlPackets         uint64
	SettingsFrames         uint64
	GoAwayFrames           uint64
	MaxPushIDFrames        uint64
	CancelPushFrames       uint64
	UnknownControlFrames   uint64
	EncoderPackets         uint64
	DecoderPackets         uint64
	RequestPackets         uint64
	RequestsHandled        uint64
	ResponsesWritten       uint64
	LocalBootstrapReady    bool
	PeerSettingsReady      bool
	ControlBytesConsumed   int
	EncoderBytesConsumed   int
	DecoderBytesConsumed   int
	Congestion             QUICCongestionSnapshot
	FlowControl            QUICFlowControlSnapshot
	KeepAlive              QUICKeepAliveSnapshot
	InitialPacketSpace     QUICPacketNumberSpaceSnapshot
	HandshakePacketSpace   QUICPacketNumberSpaceSnapshot
	ApplicationPacketSpace QUICPacketNumberSpaceSnapshot
	PeerStreamKinds           map[uint64]PeerStreamKind
	PeerConnectionIDFromFrame []byte
}

type ServerConn struct {
	Session   *Session
	Streams   PacketStreamAssembler
	requestMu sync.Mutex
	state     serverConnState
	shortHeaderDestinationConnectionIDLength int
}

type requestStreamStatus uint8

const (
	requestStreamStatusUnknown requestStreamStatus = iota
	requestStreamStatusDeferred
	requestStreamStatusActive
	requestStreamStatusCompleted
)

type serverConnState struct {
	LastMachineStep        ServerConnMachineStep
	LastStreamType         ServerConnStreamType
	LastControlStreamID    uint64
	LastEncoderStreamID    uint64
	LastDecoderStreamID    uint64
	LastControlFrame       FrameType
	LastGoAwayID           uint64
	LastMaxPushID          uint64
	LastCancelPushID       uint64
	LastRequestStreamID    uint64
	LastRequestMethod      string
	LastRequestPath        string
	LastResponseStatus     int
	InitialPackets         uint64
	HandshakePackets       uint64
	OneRTTPackets          uint64
	ApplicationPackets     uint64
	ControlPackets         uint64
	SettingsFrames         uint64
	GoAwayFrames           uint64
	MaxPushIDFrames        uint64
	CancelPushFrames       uint64
	UnknownControlFrames   uint64
	EncoderPackets         uint64
	DecoderPackets         uint64
	RequestPackets         uint64
	RequestsHandled        uint64
	ResponsesWritten       uint64
	LocalBootstrapReady    bool
	PeerSettingsReady      bool
	ControlBytesConsumed   int
	EncoderBytesConsumed   int
	DecoderBytesConsumed   int
	congestion             quicCongestionController
	flowControl            quicFlowControlState
	keepAlive              quicKeepAliveState
	PeerGoAwayReceived     bool
	PeerMaxPushIDSet       bool
	PeerConnectionClosed   bool
	initialPacketSpace     quicPacketNumberSpaceState
	handshakePacketSpace   quicPacketNumberSpaceState
	applicationPacketSpace quicPacketNumberSpaceState
	peerStreamKinds           map[uint64]PeerStreamKind
	peerStreamPrefixLens     map[uint64]uint64
	pendingPeerPackets       map[uint64][]applicationPacket
	requestStreams           map[uint64]requestStreamStatus
	peerConnectionIDFromFrame []byte
}

type applicationPacket struct {
	StreamID      uint64
	StreamOffset  uint64
	Payload       []byte
	payloadBufPtr *allocator.Buffer
	IsStreamFrame bool
	Fin           bool
}

type requestStreamFINTracker interface {
	MarkFIN(offset uint64)
	FINReceived() bool
}

func NewServerConn(session *Session, streams PacketStreamAssembler) *ServerConn {
	return &ServerConn{
		Session: session,
		Streams: streams,
		shortHeaderDestinationConnectionIDLength: DefaultShortHeaderDestinationConnectionIDLength,
	}
}

func (c *ServerConn) SetShortHeaderDestinationConnectionIDLength(length int) {
	if c == nil {
		return
	}
	if length <= 0 {
		length = DefaultShortHeaderDestinationConnectionIDLength
	}
	c.shortHeaderDestinationConnectionIDLength = length
}

func (c *ServerConn) HandlePacket(ctx context.Context, payload []byte, handler ServerRequestHandler) (ServerConnSnapshot, error) {
	if c == nil || c.Session == nil || c.Streams == nil {
		return ServerConnSnapshot{}, errors.New("http3 server connection is not configured")
	}
	if len(payload) == 0 {
		return c.Snapshot(), io.EOF
	}
	c.state.keepAlive.observeReceive(time.Now())
	if err := c.bootstrapLocalStreams(); err != nil {
		return ServerConnSnapshot{}, err
	}
	packetPayload := payload
	packetNumberSpace := QUICPacketNumberSpaceApplication
	if header, err := ParseQUICPacketHeader(payload, c.shortHeaderDestinationConnectionIDLength); err == nil {
		if space, ok := c.observeQUICPacketHeader(header); ok {
			packetNumberSpace = space
		}
		switch header.Type {
		case QUICPacketTypeInitial:
			if header.PayloadOffset > len(payload) {
				return c.Snapshot(), io.ErrUnexpectedEOF
			}
			if closePeer, err := c.observeNonApplicationPacket(packetNumberSpace, payload[header.PayloadOffset:]); err != nil {
				return ServerConnSnapshot{}, err
			} else if closePeer {
				return c.Snapshot(), nil
			}
			return c.Snapshot(), nil
		case QUICPacketTypeHandshake:
			if header.PayloadOffset > len(payload) {
				return c.Snapshot(), io.ErrUnexpectedEOF
			}
			if closePeer, err := c.observeNonApplicationPacket(packetNumberSpace, payload[header.PayloadOffset:]); err != nil {
				return ServerConnSnapshot{}, err
			} else if closePeer {
				return c.Snapshot(), nil
			}
			return c.Snapshot(), nil
		case QUICPacketTypeOneRTT:
			if header.PayloadOffset > len(payload) {
				return c.Snapshot(), io.ErrUnexpectedEOF
			}
			packetPayload = payload[header.PayloadOffset:]
		case QUICPacketTypeZeroRTT, QUICPacketTypeRetry, QUICPacketTypeVersionNegotiation:
			c.state.LastStreamType = ServerConnStreamTypeUnknown
			c.state.LastMachineStep = ServerConnMachineStepApplicationPacketIgnored
			return c.Snapshot(), nil
		}
	} else if !errors.Is(err, ErrNotQUICPacket) {
		if isPartialData(err) {
			return c.Snapshot(), nil
		}
		return ServerConnSnapshot{}, err
	}
	c.state.ApplicationPackets++
	packets, closePeer, consumedControl, err := c.parseApplicationPackets(packetNumberSpace, packetPayload)
	if err != nil {
		if isPartialData(err) {
			c.state.RequestPackets++
			c.state.LastStreamType = ServerConnStreamTypeRequest
			c.state.LastMachineStep = ServerConnMachineStepRequestStreamPending
			return c.Snapshot(), nil
		}
		return ServerConnSnapshot{}, err
	}
	if closePeer {
		return c.Snapshot(), nil
	}
	for _, packet := range packets {
		if err := c.handleApplicationPacket(ctx, packet, handler); err != nil {
			return ServerConnSnapshot{}, err
		}
	}
	if len(packets) == 0 && !consumedControl {
		c.state.LastMachineStep = ServerConnMachineStepApplicationPacketIgnored
	}
	return c.Snapshot(), nil
}

func (c *ServerConn) Snapshot() ServerConnSnapshot {
	c.requestMu.Lock()
	snapshot := ServerConnSnapshot{
		LastMachineStep:        c.state.LastMachineStep,
		LastStreamType:         c.state.LastStreamType,
		LastControlStreamID:    c.state.LastControlStreamID,
		LastEncoderStreamID:    c.state.LastEncoderStreamID,
		LastDecoderStreamID:    c.state.LastDecoderStreamID,
		LastControlFrame:       c.state.LastControlFrame,
		LastGoAwayID:           c.state.LastGoAwayID,
		LastMaxPushID:          c.state.LastMaxPushID,
		LastCancelPushID:       c.state.LastCancelPushID,
		LastRequestStreamID:    c.state.LastRequestStreamID,
		LastRequestMethod:      c.state.LastRequestMethod,
		LastRequestPath:        c.state.LastRequestPath,
		LastResponseStatus:     c.state.LastResponseStatus,
		InitialPackets:         c.state.InitialPackets,
		HandshakePackets:       c.state.HandshakePackets,
		OneRTTPackets:          c.state.OneRTTPackets,
		ApplicationPackets:     c.state.ApplicationPackets,
		ControlPackets:         c.state.ControlPackets,
		SettingsFrames:         c.state.SettingsFrames,
		GoAwayFrames:           c.state.GoAwayFrames,
		MaxPushIDFrames:        c.state.MaxPushIDFrames,
		CancelPushFrames:       c.state.CancelPushFrames,
		UnknownControlFrames:   c.state.UnknownControlFrames,
		EncoderPackets:         c.state.EncoderPackets,
		DecoderPackets:         c.state.DecoderPackets,
		RequestPackets:         c.state.RequestPackets,
		RequestsHandled:        c.state.RequestsHandled,
		ResponsesWritten:       c.state.ResponsesWritten,
		LocalBootstrapReady:    c.state.LocalBootstrapReady,
		PeerSettingsReady:      c.state.PeerSettingsReady,
		ControlBytesConsumed:   c.state.ControlBytesConsumed,
		EncoderBytesConsumed:   c.state.EncoderBytesConsumed,
		DecoderBytesConsumed:   c.state.DecoderBytesConsumed,
		Congestion:             c.state.congestion.snapshot(),
		FlowControl:            c.state.flowControl.snapshot(),
		KeepAlive:              c.state.keepAlive.snapshot(),
		InitialPacketSpace:     c.state.initialPacketSpace.snapshot(),
		HandshakePacketSpace:   c.state.handshakePacketSpace.snapshot(),
			ApplicationPacketSpace: c.state.applicationPacketSpace.snapshot(),
		}
		if len(c.state.peerConnectionIDFromFrame) > 0 {
			snapshot.PeerConnectionIDFromFrame = append([]byte(nil), c.state.peerConnectionIDFromFrame...)
		}
		c.requestMu.Unlock()
	if len(c.state.peerStreamKinds) > 0 {
		snapshot.PeerStreamKinds = make(map[uint64]PeerStreamKind, len(c.state.peerStreamKinds))
		for streamID, kind := range c.state.peerStreamKinds {
			snapshot.PeerStreamKinds[streamID] = kind
		}
	}
	return snapshot
}

func (c *ServerConn) handleApplicationPacket(ctx context.Context, packet applicationPacket, handler ServerRequestHandler) error {
	if packet.IsStreamFrame {
		kind, ok := c.lookupPeerStreamKind(packet.StreamID)
		if !ok {
			kind = PeerStreamKindUnknown
		}
		slog.Debug("http3 parsed application stream",
			slog.Uint64("stream_id", packet.StreamID),
			slog.Uint64("stream_offset", packet.StreamOffset),
			slog.Bool("fin", packet.Fin),
			slog.Int("payload_len", len(packet.Payload)),
			slog.String("known_kind", string(kind)),
		)
		if err := c.observeReceivedStreamFrame(packet); err != nil {
			return err
		}
	}
	if packet.IsStreamFrame {
		if kind, ok := c.lookupPeerStreamKind(packet.StreamID); ok {
			return c.dispatchKnownApplicationPacket(ctx, packet, kind, handler)
		}
		if isPeerUnidirectionalStream(c.Session, packet.StreamID) && packet.StreamOffset > 0 {
			c.bufferPendingPeerPacket(packet)
			c.state.LastStreamType = ServerConnStreamTypeUnknown
			c.state.LastMachineStep = ServerConnMachineStepStreamTypePending
			return nil
		}
		if isPeerRequestStream(c.Session, packet.StreamID) {
			c.storePeerStreamKind(packet.StreamID, PeerStreamKindRequest)
			return c.handleRequestStream(ctx, packet, handler)
		}
	}
	streamType, offset, err := DecodeVarInt(packet.Payload)
	if err != nil {
		if isPartialData(err) {
			return c.handleRequestStream(ctx, packet, handler)
		}
		return err
	}
	if !packet.IsStreamFrame {
		return c.handleLegacyPayload(ctx, packet, streamType, offset, handler)
	}
	return c.handleTypedStream(ctx, packet, StreamType(streamType), uint64(offset), handler)
}

func (c *ServerConn) handleLegacyPayload(ctx context.Context, packet applicationPacket, streamType uint64, offset int, handler ServerRequestHandler) error {
	switch StreamType(streamType) {
	case StreamTypeControl:
		return c.handleControlStream(packet, packet.Payload[offset:])
	case StreamTypeQPACKEncoder:
		return c.handleQPACKEncoderStream(packet)
	case StreamTypeQPACKDecoder:
		return c.handleQPACKDecoderStream(packet)
	default:
		return c.handleRequestStream(ctx, packet, handler)
	}
}

func (c *ServerConn) handleTypedStream(ctx context.Context, packet applicationPacket, streamType StreamType, prefixLen uint64, handler ServerRequestHandler) error {
	switch streamType {
	case StreamTypeControl:
		if err := c.claimCriticalStream(packet.StreamID, PeerStreamKindControl); err != nil {
			return err
		}
		c.storePeerStreamPrefixLength(packet.StreamID, prefixLen)
		c.storePeerStreamKind(packet.StreamID, PeerStreamKindControl)
		if err := c.handleControlStream(packet, packet.Payload[int(prefixLen):]); err != nil {
			return err
		}
		if err := c.flushPendingPeerPackets(ctx, packet.StreamID, handler); err != nil {
			return err
		}
		return c.flushPendingRequestPackets(ctx, handler)
	case StreamTypeQPACKEncoder:
		if err := c.claimCriticalStream(packet.StreamID, PeerStreamKindQPACKEncoder); err != nil {
			return err
		}
		c.storePeerStreamPrefixLength(packet.StreamID, prefixLen)
		c.storePeerStreamKind(packet.StreamID, PeerStreamKindQPACKEncoder)
		if err := c.handleQPACKEncoderStream(packet); err != nil {
			return err
		}
		return c.flushPendingPeerPackets(ctx, packet.StreamID, handler)
	case StreamTypeQPACKDecoder:
		if err := c.claimCriticalStream(packet.StreamID, PeerStreamKindQPACKDecoder); err != nil {
			return err
		}
		c.storePeerStreamPrefixLength(packet.StreamID, prefixLen)
		c.storePeerStreamKind(packet.StreamID, PeerStreamKindQPACKDecoder)
		if err := c.handleQPACKDecoderStream(packet); err != nil {
			return err
		}
		return c.flushPendingPeerPackets(ctx, packet.StreamID, handler)
	case StreamTypePush:
		c.storePeerStreamPrefixLength(packet.StreamID, prefixLen)
		c.storePeerStreamKind(packet.StreamID, PeerStreamKindPush)
		c.clearPendingPeerPackets(packet.StreamID)
		c.state.LastStreamType = ServerConnStreamTypePush
		c.state.LastMachineStep = ServerConnMachineStepPushStreamUnsupported
		return fmt.Errorf("http3 peer push stream is not supported: code=0x%x stream=%d", uint64(ErrStreamCreationError), packet.StreamID)
	default:
		c.storePeerStreamPrefixLength(packet.StreamID, prefixLen)
		c.storePeerStreamKind(packet.StreamID, PeerStreamKindIgnored)
		c.clearPendingPeerPackets(packet.StreamID)
		c.state.LastStreamType = ServerConnStreamTypeUnknown
		c.state.LastMachineStep = ServerConnMachineStepIgnoredUnknownStream
		return nil
	}
}

func (c *ServerConn) dispatchKnownApplicationPacket(ctx context.Context, packet applicationPacket, kind PeerStreamKind, handler ServerRequestHandler) error {
	switch kind {
	case PeerStreamKindControl:
		if err := c.handleControlStream(packet, packet.Payload); err != nil {
			return err
		}
		return c.flushPendingRequestPackets(ctx, handler)
	case PeerStreamKindQPACKEncoder:
		return c.handleQPACKEncoderStream(packet)
	case PeerStreamKindQPACKDecoder:
		return c.handleQPACKDecoderStream(packet)
	case PeerStreamKindPush:
		c.state.LastStreamType = ServerConnStreamTypePush
		c.state.LastMachineStep = ServerConnMachineStepPushStreamUnsupported
		return fmt.Errorf("http3 peer push stream is not supported: code=0x%x stream=%d", uint64(ErrStreamCreationError), packet.StreamID)
	case PeerStreamKindIgnored:
		c.state.LastStreamType = ServerConnStreamTypeUnknown
		c.state.LastMachineStep = ServerConnMachineStepIgnoredUnknownStream
		return nil
	case PeerStreamKindRequest:
		return c.handleRequestStream(ctx, packet, handler)
	default:
		c.state.LastMachineStep = ServerConnMachineStepUnknownStreamKind
		return nil
	}
}

func (c *ServerConn) bootstrapLocalStreams() error {
	if c.state.LocalBootstrapReady {
		return nil
	}
	controlWriter, err := c.Streams.OpenControlStream()
	if err != nil {
		return err
	}
	if err := c.Session.WriteControlStream(controlWriter); err != nil {
		return err
	}
	encoderWriter, err := c.Streams.OpenEncoderStream()
	if err != nil {
		return err
	}
	if err := c.Session.WriteEncoderStream(encoderWriter); err != nil {
		return err
	}
	decoderWriter, err := c.Streams.OpenDecoderStream()
	if err != nil {
		return err
	}
	if err := c.Session.WriteDecoderStream(decoderWriter); err != nil {
		return err
	}
	c.state.LocalBootstrapReady = true
	return nil
}

func (c *ServerConn) handleControlStream(packet applicationPacket, payload []byte) error {
	c.state.ControlPackets++
	c.state.LastStreamType = ServerConnStreamTypeControl
	if packet.IsStreamFrame {
		if !isPeerUnidirectionalStream(c.Session, packet.StreamID) {
			c.state.LastMachineStep = ServerConnMachineStepNonControlStream
			return nil
		}
		c.state.LastControlStreamID = packet.StreamID
	}
	relativeOffset, normalizedPayload := c.normalizePeerStreamPayload(packet)
	bufferPayload := normalizedPayloadForControl(payload, normalizedPayload)
	if !packet.IsStreamFrame {
		relativeOffset = 0
		bufferPayload = payload
	}
	if err := c.Streams.IngestControlPayload(relativeOffset, bufferPayload); err != nil {
		return err
	}
	if err := c.consumeBufferedControlFrames(); err != nil {
		return err
	}
	return c.rejectClosedCriticalStream(packet, PeerStreamKindControl)
}

func (c *ServerConn) consumeBufferedControlFrames() error {
	controlPayload := c.Streams.SnapshotControlPayload()
	offset := c.state.ControlBytesConsumed
	if offset > len(controlPayload) {
		offset = len(controlPayload)
	}
	consumedAny := false
	for offset < len(controlPayload) {
		frame, consumed, err := DecodeFrameHeader(controlPayload[offset:])
		if err != nil {
			if isPartialData(err) {
				c.state.LastMachineStep = ServerConnMachineStepControlStreamPending
				c.state.ControlBytesConsumed = offset
				if c.state.LastControlStreamID != 0 {
					c.ConsumeStreamData(c.state.LastControlStreamID, c.lookupPeerStreamPrefixLength(c.state.LastControlStreamID)+uint64(offset))
				}
				return nil
			}
			return err
		}
		payloadStart := offset + consumed
		payloadEnd := payloadStart + int(frame.Length)
		if payloadEnd > len(controlPayload) {
			c.state.LastMachineStep = ServerConnMachineStepControlStreamPending
			c.state.ControlBytesConsumed = offset
			if c.state.LastControlStreamID != 0 {
				c.ConsumeStreamData(c.state.LastControlStreamID, c.lookupPeerStreamPrefixLength(c.state.LastControlStreamID)+uint64(offset))
			}
			return nil
		}
		if err := c.applyControlFrame(frame, controlPayload[offset:payloadEnd], controlPayload[payloadStart:payloadEnd]); err != nil {
			return err
		}
		offset = payloadEnd
		consumedAny = true
	}
	c.state.ControlBytesConsumed = offset
	if consumedAny || offset == len(controlPayload) {
		if c.state.LastControlStreamID != 0 {
			c.ConsumeStreamData(c.state.LastControlStreamID, c.lookupPeerStreamPrefixLength(c.state.LastControlStreamID)+uint64(offset))
		}
		c.state.LastMachineStep = ServerConnMachineStepControlStream
		return nil
	}
	c.state.LastMachineStep = ServerConnMachineStepControlStreamPending
	return nil
}

func (c *ServerConn) applyControlFrame(frame FrameHeader, encodedFrame []byte, payload []byte) error {
	frameType := FrameType(frame.Type)
	c.state.LastControlFrame = frameType
	if !c.state.PeerSettingsReady {
		if frameType != FrameSettings {
			return fmt.Errorf("http3 control stream first frame must be settings")
		}
		controlStreamData, err := AppendVarInt(nil, uint64(StreamTypeControl))
		if err != nil {
			return err
		}
		controlStreamData = append(controlStreamData, encodedFrame...)
		if err := c.Session.ReadControlStream(bytes.NewReader(controlStreamData)); err != nil {
			return err
		}
		c.state.PeerSettingsReady = true
		c.state.SettingsFrames++
		slog.Debug("http3 peer settings ready",
			slog.Uint64("control_stream_id", c.state.LastControlStreamID),
			slog.Uint64("settings_frames", c.state.SettingsFrames),
		)
		return nil
	}
	if frameType == FrameSettings {
		return fmt.Errorf("http3 control stream must not contain duplicate settings")
	}
	if c.isUnexpectedControlFrame(frameType) {
		c.state.LastMachineStep = ServerConnMachineStepUnexpectedControlFrame
		return fmt.Errorf("http3 unexpected frame type on control stream: code=0x%x frame=0x%x", uint64(ErrFrameUnexpected), uint64(frameType))
	}
	switch frameType {
	case FrameGoAway:
		id, err := decodeSingleVarIntPayload(payload)
		if err != nil {
			return err
		}
		if err := c.validatePeerGoAwayID(id); err != nil {
			return err
		}
		c.state.LastGoAwayID = id
		c.state.PeerGoAwayReceived = true
		c.state.GoAwayFrames++
	case FrameMaxPushID:
		id, err := decodeSingleVarIntPayload(payload)
		if err != nil {
			return err
		}
		if err := c.validatePeerMaxPushID(id); err != nil {
			return err
		}
		c.state.LastMaxPushID = id
		c.state.PeerMaxPushIDSet = true
		c.state.MaxPushIDFrames++
	case FrameCancelPush:
		id, err := decodeSingleVarIntPayload(payload)
		if err != nil {
			return err
		}
		if err := c.validatePeerCancelPushID(id); err != nil {
			return err
		}
		c.state.LastCancelPushID = id
		c.state.CancelPushFrames++
	default:
		if isReservedHTTP2FrameType(frameType) {
			c.state.LastMachineStep = ServerConnMachineStepReservedControlFrame
			return fmt.Errorf("http3 reserved frame type on control stream: code=0x%x frame=0x%x", uint64(ErrFrameUnexpected), uint64(frameType))
		}
		c.state.UnknownControlFrames++
	}
	return nil
}

func (c *ServerConn) handleQPACKEncoderStream(packet applicationPacket) error {
	c.state.EncoderPackets++
	c.state.LastStreamType = ServerConnStreamTypeQPACKEncoder
	if packet.IsStreamFrame {
		if !isPeerUnidirectionalStream(c.Session, packet.StreamID) {
			c.state.LastMachineStep = ServerConnMachineStepNonQPACKEncoderStream
			return nil
		}
		c.state.LastEncoderStreamID = packet.StreamID
	}
	relativeOffset, normalizedPayload := c.normalizePeerStreamPayload(packet)
	if err := c.Streams.IngestEncoderPayload(relativeOffset, normalizedPayload); err != nil {
		return err
	}
	if err := c.consumeBufferedQPACKEncoderStream(packet.Fin); err != nil {
		return err
	}
	return c.rejectClosedCriticalStream(packet, PeerStreamKindQPACKEncoder)
}

func (c *ServerConn) handleQPACKDecoderStream(packet applicationPacket) error {
	c.state.DecoderPackets++
	c.state.LastStreamType = ServerConnStreamTypeQPACKDecoder
	if packet.IsStreamFrame {
		if !isPeerUnidirectionalStream(c.Session, packet.StreamID) {
			c.state.LastMachineStep = ServerConnMachineStepNonQPACKDecoderStream
			return nil
		}
		c.state.LastDecoderStreamID = packet.StreamID
	}
	relativeOffset, normalizedPayload := c.normalizePeerStreamPayload(packet)
	if err := c.Streams.IngestDecoderPayload(relativeOffset, normalizedPayload); err != nil {
		return err
	}
	if err := c.consumeBufferedQPACKDecoderStream(packet.Fin); err != nil {
		return err
	}
	return c.rejectClosedCriticalStream(packet, PeerStreamKindQPACKDecoder)
}

func (c *ServerConn) consumeBufferedQPACKEncoderStream(closed bool) error {
	encoderPayload := c.Streams.SnapshotEncoderPayload()
	offset := c.state.EncoderBytesConsumed
	if offset > len(encoderPayload) {
		offset = len(encoderPayload)
	}
	if offset == len(encoderPayload) {
		c.state.LastMachineStep = ServerConnMachineStepQPACKEncoderStream
		return nil
	}
	readPayload, err := qpackReadPayload(StreamTypeQPACKEncoder, offset, encoderPayload[offset:])
	if err != nil {
		return err
	}
	if err := c.Session.ReadEncoderStream(&qpackChunkState{chunk: readPayload, closed: closed}); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	c.state.EncoderBytesConsumed = len(encoderPayload)
	if c.state.LastEncoderStreamID != 0 {
		c.ConsumeStreamData(c.state.LastEncoderStreamID, c.lookupPeerStreamPrefixLength(c.state.LastEncoderStreamID)+uint64(c.state.EncoderBytesConsumed))
	}
	c.state.LastMachineStep = ServerConnMachineStepQPACKEncoderStream
	return nil
}

func (c *ServerConn) consumeBufferedQPACKDecoderStream(closed bool) error {
	decoderPayload := c.Streams.SnapshotDecoderPayload()
	offset := c.state.DecoderBytesConsumed
	if offset > len(decoderPayload) {
		offset = len(decoderPayload)
	}
	if offset == len(decoderPayload) {
		c.state.LastMachineStep = ServerConnMachineStepQPACKDecoderStream
		return nil
	}
	readPayload, err := qpackReadPayload(StreamTypeQPACKDecoder, offset, decoderPayload[offset:])
	if err != nil {
		return err
	}
	if err := c.Session.ReadDecoderStream(&qpackChunkState{chunk: readPayload, closed: closed}); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	c.state.DecoderBytesConsumed = len(decoderPayload)
	if c.state.LastDecoderStreamID != 0 {
		c.ConsumeStreamData(c.state.LastDecoderStreamID, c.lookupPeerStreamPrefixLength(c.state.LastDecoderStreamID)+uint64(c.state.DecoderBytesConsumed))
	}
	c.state.LastMachineStep = ServerConnMachineStepQPACKDecoderStream
	return nil
}

type qpackChunkState struct {
	chunk  []byte
	closed bool
	read   bool
}

func (q *qpackChunkState) Read(p []byte) (int, error) {
	if q == nil || q.read {
		return 0, io.EOF
	}
	q.read = true
	n := copy(p, q.chunk)
	if n < len(q.chunk) {
		q.chunk = q.chunk[n:]
		q.read = false
		return n, nil
	}
	return n, io.EOF
}

func (q *qpackChunkState) ReadQPACKChunkState() ([]byte, bool, error) {
	if q == nil {
		return nil, false, nil
	}
	q.read = true
	return q.chunk, q.closed, nil
}

func (c *ServerConn) handleRequestStream(ctx context.Context, packet applicationPacket, handler ServerRequestHandler) error {
	c.state.RequestPackets++
	c.state.LastStreamType = ServerConnStreamTypeRequest
	if !c.state.PeerSettingsReady {
		if packet.IsStreamFrame {
			c.storePeerStreamPrefixLength(packet.StreamID, 0)
			c.storePeerStreamKind(packet.StreamID, PeerStreamKindRequest)
			c.bufferPendingPeerPacket(packet)
		}
		c.state.LastMachineStep = ServerConnMachineStepRequestStreamPending
		return nil
	}
	if packet.IsStreamFrame && !isPeerRequestStream(c.Session, packet.StreamID) {
		c.state.LastMachineStep = ServerConnMachineStepNonRequestStream
		return nil
	}
	if packet.IsStreamFrame {
		c.storePeerStreamPrefixLength(packet.StreamID, 0)
		c.storePeerStreamKind(packet.StreamID, PeerStreamKindRequest)
	}
	streamID := packet.StreamID
	if !packet.IsStreamFrame {
		streamID = implicitRequestStreamID
	}
	if c.isRequestStreamComplete(streamID) {
		c.setRequestMachineStep(ServerConnMachineStepRequestStreamIgnored)
		return nil
	}
	stream, err := c.Streams.IngestRequestPayload(streamID, packet.StreamOffset, packet.Payload)
	if err != nil {
		return err
	}
	finReceived := !packet.IsStreamFrame
	if tracker, ok := stream.(requestStreamFINTracker); ok {
		if packet.Fin {
			tracker.MarkFIN(packet.StreamOffset + uint64(len(packet.Payload)))
		}
		finReceived = tracker.FINReceived()
	}
	if finReceived {
		c.clearDeferredRequest(streamID)
		if c.isActiveRequest(streamID) {
			c.setRequestMachineStep(ServerConnMachineStepRequestStreamActive)
			return nil
		}
	} else if c.isActiveRequest(streamID) {
		c.setRequestMachineStep(ServerConnMachineStepRequestStreamActive)
		return nil
	} else if c.isDeferredRequest(streamID) {
		c.setRequestMachineStep(ServerConnMachineStepRequestStreamPending)
		return nil
	}
	req, bodyOffset, err := c.decodeRequestHeaders(stream)
	if err != nil {
		if !finReceived {
			c.markDeferredRequest(streamID)
			c.setRequestMachineStep(ServerConnMachineStepRequestStreamPending)
			return nil
		}
		if isPartialData(err) {
			c.setRequestMachineStep(ServerConnMachineStepRequestStreamIncomplete)
			return c.writeRequestErrorResponse(stream, streamID, 400, "incomplete request")
		}
		c.setRequestMachineStep(ServerConnMachineStepRequestStreamBadRequest)
		return c.writeRequestErrorResponse(stream, streamID, 400, "bad request")
	}
	if req.Body == nil {
		reader := newRequestBodyReader(req, c.Session, stream, bodyOffset, c)
		if err := reader.discardBefore(bodyOffset); err != nil {
			return err
		}
		req.Body = reader
	}
	reserveRequestStreamBodyCapacity(stream, req, bodyOffset)
	if !finReceived {
		return c.startStreamingRequest(ctx, stream, streamID, req, handler)
	}
	return c.handleReadyRequest(ctx, stream, streamID, req, handler)
}

func reserveRequestStreamBodyCapacity(stream RequestStreamBuffer, req *core.Request, bodyOffset int) {
	if stream == nil || req == nil {
		return
	}
	contentLength := requestContentLengthHint(req)
	if contentLength <= 0 {
		return
	}
	if contentLength > int64(^uint(0)>>1)-int64(bodyOffset) {
		return
	}
	_ = stream.Reserve(bodyOffset + int(contentLength))
}

func requestContentLengthHint(req *core.Request) int64 {
	if req == nil {
		return -1
	}
	if req.ContentLength > 0 {
		return req.ContentLength
	}
	value := req.Headers.Get("Content-Length")
	if len(value) == 0 {
		return -1
	}
	length, err := strconv.ParseInt(strings.TrimSpace(string(value)), 10, 64)
	if err != nil || length <= 0 {
		return -1
	}
	return length
}

func (c *ServerConn) writeRequestErrorResponse(stream RequestStreamBuffer, streamID uint64, statusCode int, message string) error {
	if stream == nil {
		return fmt.Errorf("http3 request stream %d is nil", streamID)
	}
	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Status = core.NewStatus(statusCode)
	if resp.Status.MayHaveBody() && message != "" {
		body := []byte(message)
		resp.Headers.Set(core.HeaderContentType, []byte("text/plain; charset=utf-8"))
		resp.Headers.Set(core.HeaderContentLength, []byte(fmt.Sprintf("%d", len(body))))
		resp.SetBody(io.NopCloser(bytes.NewReader(body)))
		resp.ContentLength = int64(len(body))
	}
	if err := stream.Reset(); err != nil {
		return err
	}
	c.recordResponseStarted(streamID, statusCode)
	if err := c.Session.WriteResponse(stream, resp); err != nil {
		return err
	}
	return c.finishRequestStream(stream, streamID, statusCode)
}

func (c *ServerConn) finishRequestStream(stream RequestStreamBuffer, streamID uint64, statusCode int) error {
	c.state.flowControl.consumeAllStream(streamID)
	c.markRequestStreamComplete(streamID)
	c.clearDeferredRequest(streamID)
	c.clearActiveRequest(streamID)
	if stream != nil {
		_ = stream.CancelRead(ErrNoError)
	}
	c.recordResponseWritten(streamID, statusCode, ServerConnMachineStepRequestStreamResponse)
	return nil
}

func (c *ServerConn) decodeRequestHeaders(stream RequestStreamBuffer) (*core.Request, int, error) {
	availableLen, finReceived, err := stream.WaitForDataLen(1)
	if err != nil {
		return nil, 0, err
	}
	headerLimit := availableLen
	if headerLimit > 16 {
		headerLimit = 16
	}
	var headerScratch [16]byte
	headerBuf, err := stream.ReadRangeInto(0, headerLimit, headerScratch[:0])
	if err != nil {
		return nil, 0, err
	}
	frame, consumed, err := DecodeFrameHeader(headerBuf)
	if err != nil {
		if !finReceived && isPartialData(err) {
			return nil, 0, io.ErrUnexpectedEOF
		}
		return nil, 0, err
	}
	if FrameType(frame.Type) != FrameHeaders {
		return nil, 0, errors.New("http3 message stream missing headers")
	}
	payloadEnd := consumed + int(frame.Length)
	availableLen, finReceived, err = stream.WaitForDataLen(payloadEnd)
	if err != nil {
		return nil, 0, err
	}
	if payloadEnd > availableLen {
		if !finReceived {
			return nil, 0, io.ErrUnexpectedEOF
		}
		return nil, 0, io.ErrUnexpectedEOF
	}
	payloadBuf := core.DefaultAllocator().Get(int(frame.Length))
	defer core.DefaultAllocator().Put(payloadBuf)
	payload, err := stream.ReadRangeInto(consumed, payloadEnd, (*payloadBuf)[:0])
	if err != nil {
		return nil, 0, err
	}
	req, err := c.Session.qpack.decodeRequest(payload, requestStreamID(stream))
	if err != nil {
		return nil, 0, err
	}
	return req, payloadEnd, nil
}

func (c *ServerConn) startStreamingRequest(ctx context.Context, stream RequestStreamBuffer, streamID uint64, req *core.Request, handler ServerRequestHandler) error {
	c.markActiveRequest(streamID)
	c.recordRequestHandled(streamID, req, ServerConnMachineStepRequestStreamActive)
	go c.serveStreamingRequest(ctx, stream, streamID, req, handler)
	return nil
}

func (c *ServerConn) serveStreamingRequest(ctx context.Context, stream RequestStreamBuffer, streamID uint64, req *core.Request, handler ServerRequestHandler) {
	defer core.ReleaseRequest(req)
	resp, err := c.callRequestHandler(ctx, streamID, req, handler)
	if err != nil {
		statusCode, message := streamingRequestErrorResponse(err)
		_ = c.writeRequestErrorResponse(stream, streamID, statusCode, message)
		return
	}
	defer core.ReleaseResponse(resp)
	if err := stream.Reset(); err != nil {
		return
	}
	c.recordResponseStarted(streamID, resp.Status.Code)
	if err := c.Session.WriteResponse(stream, resp); err != nil {
		return
	}
	_ = c.finishRequestStream(stream, streamID, resp.Status.Code)
}

func (c *ServerConn) handleReadyRequest(ctx context.Context, stream RequestStreamBuffer, streamID uint64, req *core.Request, handler ServerRequestHandler) error {
	defer core.ReleaseRequest(req)
	c.recordRequestHandled(streamID, req, ServerConnMachineStepRequestStreamActive)
	resp, err := c.callRequestHandler(ctx, streamID, req, handler)
	if err != nil {
		statusCode, message := streamingRequestErrorResponse(err)
		return c.writeRequestErrorResponse(stream, streamID, statusCode, message)
	}
	defer core.ReleaseResponse(resp)
	if err := stream.Reset(); err != nil {
		return err
	}
	c.recordResponseStarted(streamID, resp.Status.Code)
	if err := c.Session.WriteResponse(stream, resp); err != nil {
		return err
	}
	return c.finishRequestStream(stream, streamID, resp.Status.Code)
}

func (c *ServerConn) callRequestHandler(ctx context.Context, streamID uint64, req *core.Request, handler ServerRequestHandler) (*core.Response, error) {
	if handler == nil {
		return nil, errors.New("http3 request handler is nil")
	}
	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("http3 request handler returned nil response for stream %d", streamID)
	}
	return resp, nil
}

func streamingRequestErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, errStreamingRequestBodyIncomplete):
		return 400, "incomplete request"
	case errors.Is(err, errStreamingRequestBodyMalformed):
		return 400, "bad request"
	default:
		return 502, "bad gateway"
	}
}

func (c *ServerConn) setRequestMachineStep(step ServerConnMachineStep) {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	c.state.LastMachineStep = step
}

func (c *ServerConn) recordRequestHandled(streamID uint64, req *core.Request, step ServerConnMachineStep) {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	c.state.RequestsHandled++
	c.state.LastRequestStreamID = streamID
	if req != nil {
		c.state.LastRequestMethod = req.Method.String()
		c.state.LastRequestPath = string(req.URI.Path)
	}
	c.state.LastMachineStep = step
}

func (c *ServerConn) recordResponseWritten(streamID uint64, statusCode int, step ServerConnMachineStep) {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	c.state.LastRequestStreamID = streamID
	c.state.LastResponseStatus = statusCode
	c.state.ResponsesWritten++
	c.state.LastMachineStep = step
}

func (c *ServerConn) recordResponseStarted(streamID uint64, statusCode int) {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	c.state.LastRequestStreamID = streamID
	c.state.LastResponseStatus = statusCode
}

func decodeSingleVarIntPayload(payload []byte) (uint64, error) {
	if len(payload) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	value, consumed, err := DecodeVarInt(payload)
	if err != nil {
		return 0, err
	}
	if consumed != len(payload) {
		return 0, fmt.Errorf("http3 control frame payload has trailing bytes")
	}
	return value, nil
}

func qpackReadPayload(streamType StreamType, offset int, payload []byte) ([]byte, error) {
	if offset > 0 {
		return payload, nil
	}
	if len(payload) > 0 && payload[0] == byte(streamType) {
		return payload, nil
	}
	framed, err := AppendVarInt(nil, uint64(streamType))
	if err != nil {
		return nil, err
	}
	framed = append(framed, payload...)
	return framed, nil
}

func (c *ServerConn) parseApplicationPackets(space QUICPacketNumberSpace, payload []byte) ([]applicationPacket, bool, bool, error) {
	if len(payload) == 0 {
		return nil, false, false, io.EOF
	}
	if !looksLikeQUICFrameSequence(payload[0]) {
		return []applicationPacket{{StreamID: implicitRequestStreamID, Payload: payload}}, false, false, nil
	}
	frames := make([]applicationPacket, 0, 2)
	consumedControl := false
	for offset := 0; offset < len(payload); {
		frameType := payload[offset]
		switch frameType {
		case quicFrameTypePadding, quicFrameTypePing:
			if frameType == quicFrameTypePing {
				c.state.keepAlive.observePing(time.Now())
			}
			offset++
			continue
		case quicFrameTypeAck, quicFrameTypeAckECN:
			ackFrame, consumed, err := ParseQUICAckFrame(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			consumedControl = true
			if err := c.HandleAckFrame(space, ackFrame); err != nil {
				return nil, false, consumedControl, err
			}
			offset += consumed
			continue
		case quicFrameTypeResetStream:
			streamID, code, _, consumed, err := decodeResetStreamFrame(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			consumedControl = true
			if err := c.HandleResetStream(streamID, code); err != nil {
				return nil, false, consumedControl, err
			}
			offset += consumed
			continue
		case quicFrameTypeStopSending:
			streamID, code, consumed, err := decodeStopSendingFrame(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			consumedControl = true
			if err := c.HandleStopSending(streamID, code); err != nil {
				return nil, false, consumedControl, err
			}
			offset += consumed
			continue
		case quicFrameTypeConnectionClose, quicFrameTypeConnectionCloseApp:
			code, _, err := decodeConnectionCloseFrame(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			consumedControl = true
			if err := c.HandleConnectionClose(code); err != nil {
				return nil, false, consumedControl, err
			}
			return nil, true, consumedControl, nil
		case quicFrameTypeMaxData:
			frame, consumed, err := ParseQUICMaxDataFrame(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			consumedControl = true
			c.HandleMaxDataFrame(frame)
			offset += consumed
			continue
		case quicFrameTypeMaxStreamData:
			frame, consumed, err := ParseQUICMaxStreamDataFrame(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			consumedControl = true
			c.HandleMaxStreamDataFrame(frame)
			offset += consumed
			continue
		case quicFrameTypeDataBlocked:
			_, consumed, err := parseQUICDataBlockedFrame(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			consumedControl = true
			offset += consumed
			continue
		case quicFrameTypeStreamDataBlocked:
			_, _, consumed, err := parseQUICStreamDataBlockedFrame(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			consumedControl = true
			offset += consumed
			continue
		case quicFrameTypeNewToken:
			// type(i) + length(i) + token(..)
			offset++
			_, consumed, err := DecodeVarInt(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			offset += consumed
			length, _, err := DecodeVarInt(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			offset += consumed
			if offset+int(length) > len(payload) {
				return nil, false, consumedControl, io.ErrUnexpectedEOF
			}
			offset += int(length)
			continue
		case quicFrameTypeMaxStreamsBidi, quicFrameTypeMaxStreamsUni:
			// type(i) + maximum_streams(i)
			_, consumed, err := DecodeVarInt(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			offset += consumed
			continue
		case quicFrameTypeStreamsBlockedBidi, quicFrameTypeStreamsBlockedUni:
			// type(i) + maximum_streams(i)
			_, consumed, err := DecodeVarInt(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			offset += consumed
			continue
		case quicFrameTypeNewConnectionID:
			// type(i) + seq(i) + retire_prior_to(i) + length(i) + cid(length) + token(16)
			offset++
			_, consumed, err := DecodeVarInt(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			offset += consumed
			_, consumed, err = DecodeVarInt(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			offset += consumed
			cidLen, consumed, err := DecodeVarInt(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			offset += consumed
			if offset+int(cidLen)+16 > len(payload) {
				return nil, false, consumedControl, io.ErrUnexpectedEOF
			}
			offset += int(cidLen) + 16
			continue
		case quicFrameTypeRetireConnectionID:
			// type(i) + seq(i)
			_, consumed, err := DecodeVarInt(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			offset += consumed
			continue
		case quicFrameTypePathChallenge, quicFrameTypePathResponse:
			// type(i) + data(8)
			if len(payload[offset:]) < 8 {
				return nil, false, consumedControl, io.ErrUnexpectedEOF
			}
			offset += 8
			continue
		case quicFrameTypeHandshakeDone:
			// type(i) only
			offset++
			continue
		}
		if frameType == quicFrameTypeCrypto {
			_, consumed, err := parseQUICCryptoFrame(payload[offset:])
			if err != nil {
				return nil, false, consumedControl, err
			}
			consumedControl = true
			offset += consumed
			continue
		}
		if !isQUICStreamFrame(frameType) {
			skipped, skipErr := skipQUICFrame(payload[offset:])
			if skipErr != nil {
				if len(frames) == 0 && !consumedControl {
					return []applicationPacket{{StreamID: implicitRequestStreamID, Payload: payload}}, false, consumedControl, nil
				}
				return nil, false, consumedControl, fmt.Errorf("unsupported quic frame type 0x%x: %w", frameType, skipErr)
			}
			slog.Debug("http3 skipping unknown quic frame", slog.Uint64("frame_type", uint64(frameType)), slog.Int("skipped_bytes", skipped))
			offset += skipped
			continue
		}
		frame, consumed, err := parseApplicationStreamFrame(payload[offset:])
		if err != nil {
			return nil, false, consumedControl, err
		}
		frames = append(frames, frame)
		offset += consumed
	}
	return frames, false, consumedControl, nil
}

func decodeResetStreamFrame(payload []byte) (uint64, ErrorCode, uint64, int, error) {
	if len(payload) == 0 || payload[0] != quicFrameTypeResetStream {
		return 0, 0, 0, 0, errors.New("http3 invalid reset_stream frame")
	}
	offset := 1
	streamID, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return 0, 0, 0, 0, err
	}
	offset += n
	code, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return 0, 0, 0, 0, err
	}
	offset += n
	finalSize, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return 0, 0, 0, 0, err
	}
	offset += n
	return streamID, ErrorCode(code), finalSize, offset, nil
}

func decodeStopSendingFrame(payload []byte) (uint64, ErrorCode, int, error) {
	if len(payload) == 0 || payload[0] != quicFrameTypeStopSending {
		return 0, 0, 0, errors.New("http3 invalid stop_sending frame")
	}
	offset := 1
	streamID, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return 0, 0, 0, err
	}
	offset += n
	code, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return 0, 0, 0, err
	}
	offset += n
	return streamID, ErrorCode(code), offset, nil
}

func decodeConnectionCloseFrame(payload []byte) (ErrorCode, int, error) {
	if len(payload) == 0 {
		return 0, 0, io.EOF
	}
	frameType := payload[0]
	if frameType != quicFrameTypeConnectionClose && frameType != quicFrameTypeConnectionCloseApp {
		return 0, 0, errors.New("http3 invalid connection_close frame")
	}
	offset := 1
	code, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return 0, 0, err
	}
	offset += n
	if frameType == quicFrameTypeConnectionClose {
		_, n, err = DecodeVarInt(payload[offset:])
		if err != nil {
			return 0, 0, err
		}
		offset += n
	}
	reasonLen, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return 0, 0, err
	}
	offset += n
	if len(payload[offset:]) < int(reasonLen) {
		return 0, 0, io.ErrUnexpectedEOF
	}
	offset += int(reasonLen)
	return ErrorCode(code), offset, nil
}

func parseApplicationStreamFrame(payload []byte) (applicationPacket, int, error) {
	if len(payload) == 0 {
		return applicationPacket{}, 0, io.EOF
	}
	frameType := payload[0]
	offset := 1
	streamID, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return applicationPacket{}, 0, err
	}
	offset += n
	streamOffset := uint64(0)
	if frameType&0x04 != 0 {
		streamOffset, n, err = DecodeVarInt(payload[offset:])
		if err != nil {
			return applicationPacket{}, 0, err
		}
		offset += n
	}
	dataLen := len(payload) - offset
	if frameType&0x02 != 0 {
		declaredLen, n, err := DecodeVarInt(payload[offset:])
		if err != nil {
			return applicationPacket{}, 0, err
		}
		offset += n
		dataLen = int(declaredLen)
	}
	if dataLen < 0 || len(payload[offset:]) < dataLen {
		return applicationPacket{}, 0, io.ErrUnexpectedEOF
	}
	consumed := offset + dataLen
	return applicationPacket{StreamID: streamID, StreamOffset: streamOffset, Payload: payload[offset:consumed], IsStreamFrame: true, Fin: frameType&0x01 != 0}, consumed, nil
}

func looksLikeQUICFrameSequence(frameType byte) bool {
	switch frameType {
	case quicFrameTypePadding, quicFrameTypePing, quicFrameTypeAck, quicFrameTypeAckECN,
		quicFrameTypeCrypto, quicFrameTypeResetStream, quicFrameTypeStopSending,
		quicFrameTypeNewToken,
		quicFrameTypeMaxStreamsBidi, quicFrameTypeMaxStreamsUni,
		quicFrameTypeStreamsBlockedBidi, quicFrameTypeStreamsBlockedUni,
		quicFrameTypeNewConnectionID, quicFrameTypeRetireConnectionID,
		quicFrameTypePathChallenge, quicFrameTypePathResponse,
		quicFrameTypeHandshakeDone,
		quicFrameTypeConnectionClose, quicFrameTypeConnectionCloseApp,
		quicFrameTypeMaxData, quicFrameTypeMaxStreamData, quicFrameTypeDataBlocked, quicFrameTypeStreamDataBlocked:
		return true
	default:
		return isQUICStreamFrame(frameType)
	}
}

func isQUICStreamFrame(frameType byte) bool {
	return frameType >= quicStreamFrameTypeBase && frameType <= quicStreamFrameTypeMax
}

// skipQUICFrame skips a single QUIC frame by reading the VarInt type and VarInt length,
// returning the total number of bytes to advance (header + payload). Returns an error if
// the payload is too short to contain a valid frame. Per RFC 9000, unknown frame types
// must be ignored.
func skipQUICFrame(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	_, typeLen, err := DecodeVarInt(payload)
	if err != nil {
		return 0, err
	}
	if len(payload) < typeLen {
		return 0, io.ErrUnexpectedEOF
	}
	frameLength, lengthLen, err := DecodeVarInt(payload[typeLen:])
	if err != nil {
		return 0, err
	}
	total := typeLen + lengthLen + int(frameLength)
	if total > len(payload) {
		return 0, io.ErrUnexpectedEOF
	}
	return total, nil
}

func (c *ServerConn) packetSpaceState(space QUICPacketNumberSpace) *quicPacketNumberSpaceState {
	switch space {
	case QUICPacketNumberSpaceInitial:
		return &c.state.initialPacketSpace
	case QUICPacketNumberSpaceHandshake:
		return &c.state.handshakePacketSpace
	case QUICPacketNumberSpaceApplication:
		return &c.state.applicationPacketSpace
	default:
		return nil
	}
}

func (c *ServerConn) observeQUICPacketHeader(header QUICPacketHeader) (QUICPacketNumberSpace, bool) {
	space, ok := packetNumberSpaceForPacketType(header.Type)
	switch header.Type {
	case QUICPacketTypeInitial:
		c.state.InitialPackets++
		c.state.LastStreamType = ServerConnStreamTypeQUICInitial
		c.state.LastMachineStep = ServerConnMachineStepQUICInitial
	case QUICPacketTypeHandshake:
		c.state.HandshakePackets++
		c.state.LastStreamType = ServerConnStreamTypeQUICHandshake
		c.state.LastMachineStep = ServerConnMachineStepQUICHandshake
	case QUICPacketTypeOneRTT:
		c.state.OneRTTPackets++
		c.state.LastStreamType = ServerConnStreamTypeQUIC1RTT
		c.state.LastMachineStep = ServerConnMachineStepQUIC1RTT
	}
	if !ok {
		return QUICPacketNumberSpaceUnknown, false
	}
	if state := c.packetSpaceState(space); state != nil {
		state.observePacket(header.PacketNumber, header.PacketNumberLength)
	}
	return space, true
}

func (c *ServerConn) HandleAckFrame(space QUICPacketNumberSpace, frame QUICAckFrame) error {
	return c.handleAckFrameAt(space, frame, time.Now())
}

func (c *ServerConn) handleAckFrameAt(space QUICPacketNumberSpace, frame QUICAckFrame, now time.Time) error {
	if c == nil {
		return errors.New("http3 server connection is not configured")
	}
	state := c.packetSpaceState(space)
	if state == nil {
		return nil
	}
	events := state.observeAckAt(frame, now)
	c.state.congestion.onPacketsAcked(events)
	c.state.congestion.onPacketsLost(events)
	return nil
}

func (c *ServerConn) RecordSentPacket(space QUICPacketNumberSpace, packet QUICSentPacket) error {
	if c == nil {
		return errors.New("http3 server connection is not configured")
	}
	state := c.packetSpaceState(space)
	if state == nil {
		return nil
	}
	if err := c.state.flowControl.observeSentPacket(packet); err != nil {
		return err
	}
	if err := state.recordSentPacket(packet); err != nil {
		return err
	}
	c.state.keepAlive.observeSend(packet.SentAt)
	c.state.congestion.onPacketSent(packet)
	return nil
}

func (c *ServerConn) HandleMaxDataFrame(frame QUICMaxDataFrame) {
	if c == nil {
		return
	}
	c.state.flowControl.observeMaxData(frame.MaximumData)
}

func (c *ServerConn) HandleMaxStreamDataFrame(frame QUICMaxStreamDataFrame) {
	if c == nil {
		return
	}
	c.state.flowControl.observeMaxStreamData(frame.StreamID, frame.MaximumStreamData)
}

func (c *ServerConn) FlowControlSnapshot() QUICFlowControlSnapshot {
	if c == nil {
		return QUICFlowControlSnapshot{}
	}
	return c.Snapshot().FlowControl
}

func (c *ServerConn) CanSendStreamData(streamID uint64, offset uint64, payloadLen int) bool {
	if c == nil {
		return false
	}
	return c.state.flowControl.canSendStream(streamID, offset, payloadLen)
}

func (c *ServerConn) AvailableStreamSendWindow(streamID uint64) uint64 {
	if c == nil {
		return 0
	}
	return c.state.flowControl.availableStreamWindow(streamID)
}

func (c *ServerConn) DrainPendingFlowControlFrames() ([]byte, error) {
	if c == nil {
		return nil, errors.New("http3 server connection is not configured")
	}
	return c.state.flowControl.drainPendingMaxFrames()
}

func (c *ServerConn) ConsumeStreamData(streamID uint64, consumedThrough uint64) {
	if c == nil {
		return
	}
	c.state.flowControl.consumeStream(streamID, consumedThrough)
}

func (c *ServerConn) observeReceivedStreamFrame(packet applicationPacket) error {
	if c == nil || !packet.IsStreamFrame {
		return nil
	}
	return c.state.flowControl.observeReceivedStream(packet.StreamID, packet.StreamOffset, len(packet.Payload))
}

func (c *ServerConn) AdvanceLossRecovery(now time.Time) error {
	if c == nil {
		return errors.New("http3 server connection is not configured")
	}
	for _, space := range []QUICPacketNumberSpace{QUICPacketNumberSpaceInitial, QUICPacketNumberSpaceHandshake, QUICPacketNumberSpaceApplication} {
		state := c.packetSpaceState(space)
		if state == nil {
			continue
		}
		events := state.advanceLossRecovery(now)
		c.state.congestion.onPacketsLost(events)
	}
	return nil
}

func (c *ServerConn) CongestionSnapshot() QUICCongestionSnapshot {
	if c == nil {
		return QUICCongestionSnapshot{}
	}
	return c.Snapshot().Congestion
}

func (c *ServerConn) CanSend(bytes uint64) bool {
	if c == nil {
		return false
	}
	return c.state.congestion.canSend(bytes)
}

func (c *ServerConn) AvailableCongestionWindow() uint64 {
	if c == nil {
		return 0
	}
	return c.state.congestion.availableWindow()
}

func (c *ServerConn) DrainPendingRetransmissions(space QUICPacketNumberSpace) ([]QUICPendingRetransmission, error) {
	if c == nil {
		return nil, errors.New("http3 server connection is not configured")
	}
	state := c.packetSpaceState(space)
	if state == nil {
		return nil, nil
	}
	return state.drainPendingRetransmissions(), nil
}

func (c *ServerConn) DrainPendingAckFrame(space QUICPacketNumberSpace) ([]byte, error) {
	if c == nil {
		return nil, errors.New("http3 server connection is not configured")
	}
	state := c.packetSpaceState(space)
	if state == nil {
		return nil, nil
	}
	return state.drainAckFrame()
}

func (c *ServerConn) KeepAliveSnapshot() QUICKeepAliveSnapshot {
	if c == nil {
		return QUICKeepAliveSnapshot{}
	}
	return c.Snapshot().KeepAlive
}

func (c *ServerConn) ArmKeepAlive(now time.Time, interval time.Duration) bool {
	if c == nil {
		return false
	}
	return c.armKeepAliveAt(now, interval)
}

func (c *ServerConn) armKeepAliveAt(now time.Time, interval time.Duration) bool {
	if c == nil {
		return false
	}
	return c.state.keepAlive.arm(now, interval)
}

func (c *ServerConn) DrainPendingPingFrame() ([]byte, error) {
	return c.drainPendingPingFrameAt(time.Now())
}

func (c *ServerConn) drainPendingPingFrameAt(now time.Time) ([]byte, error) {
	if c == nil {
		return nil, errors.New("http3 server connection is not configured")
	}
	return c.state.keepAlive.drainPingFrame(now), nil
}

func (c *ServerConn) IsIdle(now time.Time, timeout time.Duration) bool {
	if c == nil {
		return false
	}
	return c.isIdleAt(now, timeout)
}

func (c *ServerConn) isIdleAt(now time.Time, timeout time.Duration) bool {
	if c == nil {
		return false
	}
	return c.state.keepAlive.isIdle(now, timeout)
}

func (c *ServerConn) observeNonApplicationPacket(space QUICPacketNumberSpace, payload []byte) (bool, error) {
	for offset := 0; offset < len(payload); {
		frameType := payload[offset]
		switch frameType {
		case quicFrameTypePadding, quicFrameTypePing:
			if frameType == quicFrameTypePing {
				c.state.keepAlive.observePing(time.Now())
			}
			offset++
		case quicFrameTypeAck, quicFrameTypeAckECN:
			ackFrame, consumed, err := ParseQUICAckFrame(payload[offset:])
			if err != nil {
				return false, err
			}
			if err := c.HandleAckFrame(space, ackFrame); err != nil {
				return false, err
			}
			offset += consumed
		case quicFrameTypeCrypto:
			_, consumed, err := parseQUICCryptoFrame(payload[offset:])
			if err != nil {
				return false, err
			}
			offset += consumed
		case quicFrameTypeMaxData:
			frame, consumed, err := ParseQUICMaxDataFrame(payload[offset:])
			if err != nil {
				return false, err
			}
			c.HandleMaxDataFrame(frame)
			offset += consumed
		case quicFrameTypeMaxStreamData:
			frame, consumed, err := ParseQUICMaxStreamDataFrame(payload[offset:])
			if err != nil {
				return false, err
			}
			c.HandleMaxStreamDataFrame(frame)
			offset += consumed
		case quicFrameTypeDataBlocked:
			_, consumed, err := parseQUICDataBlockedFrame(payload[offset:])
			if err != nil {
				return false, err
			}
			offset += consumed
		case quicFrameTypeStreamDataBlocked:
			_, _, consumed, err := parseQUICStreamDataBlockedFrame(payload[offset:])
			if err != nil {
				return false, err
			}
			offset += consumed
		case quicFrameTypeConnectionClose, quicFrameTypeConnectionCloseApp:
			code, consumed, err := decodeConnectionCloseFrame(payload[offset:])
			if err != nil {
				return false, err
			}
			if err := c.HandleConnectionClose(code); err != nil {
				return false, err
			}
			offset += consumed
			return true, nil
		default:
			return false, fmt.Errorf("unsupported quic non-application frame type 0x%x", frameType)
		}
	}
	return false, nil
}

func isPeerRequestStream(session *Session, streamID uint64) bool {
	if session == nil {
		return false
	}
	if session.IsClient {
		return streamID%4 == 1
	}
	return streamID%4 == 0
}

func isPeerUnidirectionalStream(session *Session, streamID uint64) bool {
	if session == nil {
		return false
	}
	if session.IsClient {
		return streamID%4 == 3
	}
	return streamID%4 == 2
}

func isPartialData(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "unexpected eof")
}

func normalizedPayloadForControl(fallback []byte, normalized []byte) []byte {
	if normalized != nil {
		return normalized
	}
	return fallback[:0]
}

func (c *ServerConn) normalizePeerStreamPayload(packet applicationPacket) (uint64, []byte) {
	if !packet.IsStreamFrame {
		return 0, packet.Payload
	}
	prefixLen := c.lookupPeerStreamPrefixLength(packet.StreamID)
	if prefixLen == 0 {
		return packet.StreamOffset, packet.Payload
	}
	if packet.StreamOffset >= prefixLen {
		return packet.StreamOffset - prefixLen, packet.Payload
	}
	skip := int(prefixLen - packet.StreamOffset)
	if skip >= len(packet.Payload) {
		return 0, nil
	}
	return 0, packet.Payload[skip:]
}

func (c *ServerConn) lookupPeerStreamKind(streamID uint64) (PeerStreamKind, bool) {
	if c.state.peerStreamKinds == nil {
		return PeerStreamKindUnknown, false
	}
	kind, ok := c.state.peerStreamKinds[streamID]
	return kind, ok
}

func (c *ServerConn) storePeerStreamKind(streamID uint64, kind PeerStreamKind) {
	if kind == PeerStreamKindUnknown {
		return
	}
	if c.state.peerStreamKinds == nil {
		c.state.peerStreamKinds = make(map[uint64]PeerStreamKind)
	}
	c.state.peerStreamKinds[streamID] = kind
}

func (c *ServerConn) claimCriticalStream(streamID uint64, kind PeerStreamKind) error {
	if streamID == implicitRequestStreamID {
		return nil
	}
	existing, ok := c.lookupExistingCriticalStream(kind)
	if !ok || existing == streamID {
		return nil
	}
	c.state.LastMachineStep = ServerConnMachineStepDuplicateCriticalStream
	c.state.LastStreamType = serverConnStreamTypeForPeerKind(kind)
	return fmt.Errorf("http3 duplicate critical stream: code=0x%x kind=%s existing=%d new=%d", uint64(ErrStreamCreationError), kind, existing, streamID)
}

func (c *ServerConn) rejectClosedCriticalStream(packet applicationPacket, kind PeerStreamKind) error {
	if !packet.IsStreamFrame || !packet.Fin {
		return nil
	}
	c.state.LastMachineStep = ServerConnMachineStepCriticalStreamClosed
	c.state.LastStreamType = serverConnStreamTypeForPeerKind(kind)
	return fmt.Errorf("http3 critical stream closed: code=0x%x kind=%s stream=%d", uint64(ErrClosedCriticalStream), kind, packet.StreamID)
}

func serverConnStreamTypeForPeerKind(kind PeerStreamKind) ServerConnStreamType {
	switch kind {
	case PeerStreamKindControl:
		return ServerConnStreamTypeControl
	case PeerStreamKindQPACKEncoder:
		return ServerConnStreamTypeQPACKEncoder
	case PeerStreamKindQPACKDecoder:
		return ServerConnStreamTypeQPACKDecoder
	case PeerStreamKindPush:
		return ServerConnStreamTypePush
	case PeerStreamKindRequest:
		return ServerConnStreamTypeRequest
	default:
		return ServerConnStreamTypeUnknown
	}
}

func (c *ServerConn) validatePeerGoAwayID(id uint64) error {
	if c.Session != nil && c.Session.IsClient && id%4 != 0 {
		c.state.LastMachineStep = ServerConnMachineStepGoAwayIDInvalidType
		return fmt.Errorf("http3 goaway stream id has invalid type: code=0x%x id=%d", uint64(ErrIDError), id)
	}
	if c.state.PeerGoAwayReceived && id > c.state.LastGoAwayID {
		c.state.LastMachineStep = ServerConnMachineStepGoAwayIDIncreased
		return fmt.Errorf("http3 goaway id increased: code=0x%x previous=%d current=%d", uint64(ErrIDError), c.state.LastGoAwayID, id)
	}
	return nil
}

func (c *ServerConn) validatePeerMaxPushID(id uint64) error {
	if c.state.PeerMaxPushIDSet && id < c.state.LastMaxPushID {
		c.state.LastMachineStep = ServerConnMachineStepMaxPushIDDecreased
		return fmt.Errorf("http3 max push id decreased: code=0x%x previous=%d current=%d", uint64(ErrIDError), c.state.LastMaxPushID, id)
	}
	return nil
}

func (c *ServerConn) validatePeerCancelPushID(id uint64) error {
	if c.state.PeerMaxPushIDSet && id > c.state.LastMaxPushID {
		c.state.LastMachineStep = ServerConnMachineStepCancelPushIDExceedsLimit
		return fmt.Errorf("http3 cancel push id exceeds limit: code=0x%x limit=%d current=%d", uint64(ErrIDError), c.state.LastMaxPushID, id)
	}
	c.state.LastMachineStep = ServerConnMachineStepCancelPushWithoutPromise
	return fmt.Errorf("http3 cancel push without promised push: code=0x%x push=%d", uint64(ErrIDError), id)
}

func (c *ServerConn) isUnexpectedControlFrame(frameType FrameType) bool {
	switch frameType {
	case FrameData, FrameHeaders, FramePushPromise:
		return true
	case FrameMaxPushID:
		return c.Session != nil && c.Session.IsClient
	default:
		return false
	}
}

func (c *ServerConn) lookupExistingCriticalStream(kind PeerStreamKind) (uint64, bool) {
	switch kind {
	case PeerStreamKindControl:
		if c.state.LastControlStreamID == 0 {
			return 0, false
		}
		return c.state.LastControlStreamID, true
	case PeerStreamKindQPACKEncoder:
		if c.state.LastEncoderStreamID == 0 {
			return 0, false
		}
		return c.state.LastEncoderStreamID, true
	case PeerStreamKindQPACKDecoder:
		if c.state.LastDecoderStreamID == 0 {
			return 0, false
		}
		return c.state.LastDecoderStreamID, true
	default:
		return 0, false
	}
}

func (c *ServerConn) storePeerStreamPrefixLength(streamID uint64, prefixLen uint64) {
	if c.state.peerStreamPrefixLens == nil {
		c.state.peerStreamPrefixLens = make(map[uint64]uint64)
	}
	if _, ok := c.state.peerStreamPrefixLens[streamID]; ok {
		return
	}
	c.state.peerStreamPrefixLens[streamID] = prefixLen
}

func (c *ServerConn) bufferPendingPeerPacket(packet applicationPacket) {
	if !packet.IsStreamFrame {
		return
	}
	if c.state.pendingPeerPackets == nil {
		c.state.pendingPeerPackets = make(map[uint64][]applicationPacket)
	}
	if len(packet.Payload) > 0 {
		bufPtr := core.DefaultAllocator().Get(len(packet.Payload))
		buf := (*bufPtr)[:len(packet.Payload)]
		copy(buf, packet.Payload)
		packet.Payload = buf
		packet.payloadBufPtr = bufPtr
	}
	c.state.pendingPeerPackets[packet.StreamID] = append(c.state.pendingPeerPackets[packet.StreamID], packet)
}

func (c *ServerConn) flushPendingPeerPackets(ctx context.Context, streamID uint64, handler ServerRequestHandler) error {
	if c.state.pendingPeerPackets == nil {
		return nil
	}
	packets := c.state.pendingPeerPackets[streamID]
	if len(packets) == 0 {
		return nil
	}
	sort.Slice(packets, func(i, j int) bool {
		if packets[i].StreamOffset == packets[j].StreamOffset {
			return len(packets[i].Payload) < len(packets[j].Payload)
		}
		return packets[i].StreamOffset < packets[j].StreamOffset
	})
	delete(c.state.pendingPeerPackets, streamID)
	defer releaseApplicationPackets(packets)
	for _, pending := range packets {
		kind, ok := c.lookupPeerStreamKind(streamID)
		if !ok {
			break
		}
		if err := c.dispatchKnownApplicationPacket(ctx, pending, kind, handler); err != nil {
			return err
		}
	}
	return nil
}

func (c *ServerConn) flushPendingRequestPackets(ctx context.Context, handler ServerRequestHandler) error {
	if c == nil || !c.state.PeerSettingsReady || c.state.pendingPeerPackets == nil {
		return nil
	}
	streamIDs := make([]uint64, 0, len(c.state.pendingPeerPackets))
	for streamID, packets := range c.state.pendingPeerPackets {
		if len(packets) == 0 {
			continue
		}
		if kind, ok := c.lookupPeerStreamKind(streamID); !ok || kind != PeerStreamKindRequest {
			continue
		}
		streamIDs = append(streamIDs, streamID)
	}
	if len(streamIDs) == 0 {
		return nil
	}
	sort.Slice(streamIDs, func(i, j int) bool {
		return streamIDs[i] < streamIDs[j]
	})
	for _, streamID := range streamIDs {
		if err := c.flushPendingPeerPackets(ctx, streamID, handler); err != nil {
			return err
		}
	}
	return nil
}

func (c *ServerConn) clearPendingPeerPackets(streamID uint64) {
	if c.state.pendingPeerPackets == nil {
		return
	}
	packets := c.state.pendingPeerPackets[streamID]
	delete(c.state.pendingPeerPackets, streamID)
	releaseApplicationPackets(packets)
}

func releaseApplicationPackets(packets []applicationPacket) {
	for i := range packets {
		if packets[i].payloadBufPtr != nil {
			_ = core.DefaultAllocator().Put(packets[i].payloadBufPtr)
			packets[i].payloadBufPtr = nil
			packets[i].Payload = nil
		}
	}
}

func (c *ServerConn) isRequestStreamComplete(streamID uint64) bool {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	return c.requestStreamStatusLocked(streamID) == requestStreamStatusCompleted
}

func (c *ServerConn) RequestStreamComplete(streamID uint64) bool {
	if c == nil {
		return false
	}
	return c.isRequestStreamComplete(streamID)
}

func (c *ServerConn) HandleResetStream(streamID uint64, code ErrorCode) error {
	if c == nil {
		return errors.New("http3 server connection is not configured")
	}
	c.abortRequestStream(streamID, code, true)
	c.requestMu.Lock()
	c.state.LastRequestStreamID = streamID
	c.state.LastMachineStep = ServerConnMachineStepRequestStreamReset
	c.requestMu.Unlock()
	return nil
}

func (c *ServerConn) HandleStopSending(streamID uint64, code ErrorCode) error {
	if c == nil {
		return errors.New("http3 server connection is not configured")
	}
	c.abortRequestStream(streamID, code, false)
	c.requestMu.Lock()
	c.state.LastRequestStreamID = streamID
	c.state.LastMachineStep = ServerConnMachineStepRequestStreamStopSending
	c.requestMu.Unlock()
	return nil
}

func (c *ServerConn) HandleConnectionClose(code ErrorCode) error {
	if c == nil {
		return errors.New("http3 server connection is not configured")
	}
	c.abortAllRequestStreams(code)
	c.requestMu.Lock()
	c.state.PeerConnectionClosed = true
	c.state.LastMachineStep = ServerConnMachineStepConnectionClose
	c.requestMu.Unlock()
	return nil
}

func (c *ServerConn) PeerConnectionClosed() bool {
	if c == nil {
		return false
	}
	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	return c.state.PeerConnectionClosed
}

func (c *ServerConn) markRequestStreamComplete(streamID uint64) {
	c.setRequestStreamStatus(streamID, requestStreamStatusCompleted)
}

func (c *ServerConn) abortRequestStream(streamID uint64, code ErrorCode, cancelRead bool) {
	if c == nil {
		return
	}
	if stream := c.Streams.RequestStream(streamID); stream != nil {
		if cancelRead {
			_ = stream.CancelRead(code)
		}
		_ = stream.CancelWrite(code)
	}
	c.state.flowControl.consumeAllStream(streamID)
	c.clearPendingPeerPackets(streamID)
	c.clearDeferredRequest(streamID)
	c.clearActiveRequest(streamID)
	c.markRequestStreamComplete(streamID)
}

func (c *ServerConn) abortAllRequestStreams(code ErrorCode) {
	if c == nil {
		return
	}
	c.requestMu.Lock()
	streamIDs := make([]uint64, 0, len(c.state.requestStreams))
	for streamID := range c.state.requestStreams {
		streamIDs = append(streamIDs, streamID)
	}
	c.requestMu.Unlock()
	for _, streamID := range streamIDs {
		c.abortRequestStream(streamID, code, true)
	}
	for streamID, kind := range c.state.peerStreamKinds {
		if kind == PeerStreamKindRequest {
			c.abortRequestStream(streamID, code, true)
		}
	}
}

func (c *ServerConn) isDeferredRequest(streamID uint64) bool {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	return c.requestStreamStatusLocked(streamID) == requestStreamStatusDeferred
}

func (c *ServerConn) markDeferredRequest(streamID uint64) {
	c.setRequestStreamStatus(streamID, requestStreamStatusDeferred)
}

func (c *ServerConn) clearDeferredRequest(streamID uint64) {
	c.clearRequestStreamStatus(streamID, requestStreamStatusDeferred)
}

func (c *ServerConn) isActiveRequest(streamID uint64) bool {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	return c.requestStreamStatusLocked(streamID) == requestStreamStatusActive
}

func (c *ServerConn) markActiveRequest(streamID uint64) {
	c.setRequestStreamStatus(streamID, requestStreamStatusActive)
}

func (c *ServerConn) clearActiveRequest(streamID uint64) {
	c.clearRequestStreamStatus(streamID, requestStreamStatusActive)
}

func (c *ServerConn) requestStreamStatusLocked(streamID uint64) requestStreamStatus {
	if c.state.requestStreams == nil {
		return requestStreamStatusUnknown
	}
	return c.state.requestStreams[streamID]
}

func (c *ServerConn) setRequestStreamStatus(streamID uint64, status requestStreamStatus) {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	if c.state.requestStreams == nil {
		c.state.requestStreams = make(map[uint64]requestStreamStatus)
	}
	c.state.requestStreams[streamID] = status
}

func (c *ServerConn) clearRequestStreamStatus(streamID uint64, status requestStreamStatus) {
	c.requestMu.Lock()
	defer c.requestMu.Unlock()
	if c.state.requestStreams == nil {
		return
	}
	if c.state.requestStreams[streamID] == status {
		delete(c.state.requestStreams, streamID)
	}
}

func (c *ServerConn) lookupPeerStreamPrefixLength(streamID uint64) uint64 {
	if c.state.peerStreamPrefixLens == nil {
		return 0
	}
	return c.state.peerStreamPrefixLens[streamID]
}

func snapshotRequestPayload(stream RequestStreamBuffer) []byte {
	if stream == nil {
		return nil
	}
	chunkReader, ok := stream.(interface{ Snapshot() []byte })
	if ok {
		return chunkReader.Snapshot()
	}
	reader := io.Reader(stream)
	buf, _ := io.ReadAll(reader)
	return buf
}
