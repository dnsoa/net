package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"time"

	"github.com/dnsoa/net/httpx/core"
)

var ErrServerPeerConnectionUnavailable = errors.New("http3 server peer connection is not configured")

type ServerPeerConnection struct {
	session   *Session
	transport *Transport
	streams   PacketStreamAssembler
	server    *ServerConn
	tlsServer *QUICTLSHandshake
}

func NewServerPeerConnection(session *Session, streams PacketStreamAssembler) (*ServerPeerConnection, error) {
	if session == nil || streams == nil {
		return nil, ErrServerPeerConnectionUnavailable
	}
	controlOpener, ok := streams.(ControlStreamOpener)
	if !ok {
		return nil, ErrServerPeerConnectionUnavailable
	}
	requestOpener, ok := streams.(RequestStreamOpener)
	if !ok {
		return nil, ErrServerPeerConnectionUnavailable
	}
	return &ServerPeerConnection{
		session:   session,
		transport: NewTransport(session, controlOpener, requestOpener),
		streams:   streams,
		server:    NewServerConn(session, streams),
	}, nil
}

func (c *ServerPeerConnection) SetShortHeaderDestinationConnectionIDLength(length int) {
	if c == nil {
		return
	}
	if c.server != nil {
		c.server.SetShortHeaderDestinationConnectionIDLength(length)
	}
}

func (c *ServerPeerConnection) Session() *Session {
	if c == nil {
		return nil
	}
	return c.session
}

func (c *ServerPeerConnection) Transport() *Transport {
	if c == nil {
		return nil
	}
	return c.transport
}

func (c *ServerPeerConnection) HandlePacket(ctx context.Context, payload []byte, handler ServerRequestHandler) (ServerConnSnapshot, error) {
	if c == nil || c.server == nil {
		return ServerConnSnapshot{}, ErrServerPeerConnectionUnavailable
	}
	if consumed, snapshot, err := c.handleTLSPacket(ctx, payload); consumed || err != nil {
		return snapshot, err
	}
	return c.server.HandlePacket(ctx, payload, handler)
}

func (c *ServerPeerConnection) Snapshot() ServerConnSnapshot {
	if c == nil || c.server == nil {
		return ServerConnSnapshot{}
	}
	return c.server.Snapshot()
}

func (c *ServerPeerConnection) RequestStream(streamID uint64) RequestStreamBuffer {
	if c == nil || c.streams == nil {
		return nil
	}
	return c.streams.RequestStream(streamID)
}

func (c *ServerPeerConnection) RequestStreamComplete(streamID uint64) bool {
	if c == nil || c.server == nil {
		return false
	}
	return c.server.RequestStreamComplete(streamID)
}

func (c *ServerPeerConnection) DrainPendingAckFrame(space QUICPacketNumberSpace) ([]byte, error) {
	if c == nil || c.server == nil {
		return nil, ErrServerPeerConnectionUnavailable
	}
	return c.server.DrainPendingAckFrame(space)
}

func (c *ServerPeerConnection) RecordSentPacket(space QUICPacketNumberSpace, packet QUICSentPacket) error {
	if c == nil || c.server == nil {
		return ErrServerPeerConnectionUnavailable
	}
	return c.server.RecordSentPacket(space, packet)
}

func (c *ServerPeerConnection) AdvanceLossRecovery(now time.Time) error {
	if c == nil || c.server == nil {
		return ErrServerPeerConnectionUnavailable
	}
	return c.server.AdvanceLossRecovery(now)
}

func (c *ServerPeerConnection) DrainPendingRetransmissions(space QUICPacketNumberSpace) ([]QUICPendingRetransmission, error) {
	if c == nil || c.server == nil {
		return nil, ErrServerPeerConnectionUnavailable
	}
	return c.server.DrainPendingRetransmissions(space)
}

func (c *ServerPeerConnection) CongestionSnapshot() QUICCongestionSnapshot {
	if c == nil || c.server == nil {
		return QUICCongestionSnapshot{}
	}
	return c.server.CongestionSnapshot()
}

func (c *ServerPeerConnection) FlowControlSnapshot() QUICFlowControlSnapshot {
	if c == nil || c.server == nil {
		return QUICFlowControlSnapshot{}
	}
	return c.server.FlowControlSnapshot()
}

func (c *ServerPeerConnection) CanSendStreamData(streamID uint64, offset uint64, payloadLen int) bool {
	if c == nil || c.server == nil {
		return false
	}
	return c.server.CanSendStreamData(streamID, offset, payloadLen)
}

func (c *ServerPeerConnection) AvailableStreamSendWindow(streamID uint64) uint64 {
	if c == nil || c.server == nil {
		return 0
	}
	return c.server.AvailableStreamSendWindow(streamID)
}

func (c *ServerPeerConnection) DrainPendingFlowControlFrames() ([]byte, error) {
	if c == nil || c.server == nil {
		return nil, ErrServerPeerConnectionUnavailable
	}
	return c.server.DrainPendingFlowControlFrames()
}

func (c *ServerPeerConnection) SetPeerMaxData(maxData uint64) {
	if c == nil || c.server == nil {
		return
	}
	c.server.SetPeerMaxData(maxData)
}

func (c *ServerPeerConnection) SetPeerStreamMaxData(streamID uint64, maxData uint64) {
	if c == nil || c.server == nil {
		return
	}
	c.server.SetPeerStreamMaxData(streamID, maxData)
}

func (c *ServerPeerConnection) KeepAliveSnapshot() QUICKeepAliveSnapshot {
	if c == nil || c.server == nil {
		return QUICKeepAliveSnapshot{}
	}
	return c.server.KeepAliveSnapshot()
}

func (c *ServerPeerConnection) ArmKeepAlive(now time.Time, interval time.Duration) bool {
	if c == nil || c.server == nil {
		return false
	}
	return c.server.ArmKeepAlive(now, interval)
}

func (c *ServerPeerConnection) DrainPendingPingFrame() ([]byte, error) {
	if c == nil || c.server == nil {
		return nil, ErrServerPeerConnectionUnavailable
	}
	return c.server.DrainPendingPingFrame()
}

func (c *ServerPeerConnection) IsIdle(now time.Time, timeout time.Duration) bool {
	if c == nil || c.server == nil {
		return false
	}
	return c.server.IsIdle(now, timeout)
}

func (c *ServerPeerConnection) CanSend(bytes uint64) bool {
	if c == nil || c.server == nil {
		return false
	}
	return c.server.CanSend(bytes)
}

func (c *ServerPeerConnection) AvailableCongestionWindow() uint64 {
	if c == nil || c.server == nil {
		return 0
	}
	return c.server.AvailableCongestionWindow()
}

func (c *ServerPeerConnection) PeerConnectionClosed() bool {
	if c == nil || c.server == nil {
		return false
	}
	return c.server.PeerConnectionClosed()
}

func (c *ServerPeerConnection) Close(code ErrorCode) error {
	if c == nil || c.server == nil {
		return nil
	}
	return c.server.HandleConnectionClose(code)
}

func (c *ServerPeerConnection) LocalControlPayload() []byte {
	if c == nil || c.streams == nil {
		return nil
	}
	if snapshotter, ok := c.streams.(interface{ SnapshotLocalControlPayload() []byte }); ok {
		return snapshotter.SnapshotLocalControlPayload()
	}
	return nil
}

func (c *ServerPeerConnection) LocalEncoderPayload() []byte {
	if c == nil || c.streams == nil {
		return nil
	}
	if snapshotter, ok := c.streams.(interface{ SnapshotLocalEncoderPayload() []byte }); ok {
		return snapshotter.SnapshotLocalEncoderPayload()
	}
	return nil
}

func (c *ServerPeerConnection) LocalDecoderPayload() []byte {
	if c == nil || c.streams == nil {
		return nil
	}
	if snapshotter, ok := c.streams.(interface{ SnapshotLocalDecoderPayload() []byte }); ok {
		return snapshotter.SnapshotLocalDecoderPayload()
	}
	return nil
}

func (c *ServerPeerConnection) EnableTLSServer(config *tls.Config, transportParams []byte) error {
	if c == nil {
		return ErrServerPeerConnectionUnavailable
	}
	handshake, err := NewQUICTLSServerHandshake(config, transportParams)
	if err != nil {
		return err
	}
	c.tlsServer = handshake
	return nil
}

func (c *ServerPeerConnection) StartTLS(ctx context.Context) error {
	if c == nil || c.tlsServer == nil {
		return ErrQUICTLSUnavailable
	}
	return c.tlsServer.Start(ctx)
}

func (c *ServerPeerConnection) HandleTLSCryptoFrames(packetType QUICPacketType, payload []byte) error {
	if c == nil || c.tlsServer == nil {
		return ErrQUICTLSUnavailable
	}
	level, ok := QUICPacketTypeEncryptionLevel(packetType)
	if !ok {
		return ErrQUICTLSUnavailable
	}
	return c.tlsServer.HandleCryptoFrames(level, payload)
}

func (c *ServerPeerConnection) DrainTLSCryptoFrames(level tls.QUICEncryptionLevel) ([]byte, error) {
	if c == nil || c.tlsServer == nil {
		return nil, ErrQUICTLSUnavailable
	}
	return c.tlsServer.DrainCryptoFrames(level)
}

func (c *ServerPeerConnection) TLSPeerTransportParameters() []byte {
	if c == nil || c.tlsServer == nil {
		return nil
	}
	return c.tlsServer.PeerTransportParameters()
}

func (c *ServerPeerConnection) TLSHandshakeComplete() bool {
	if c == nil || c.tlsServer == nil {
		return false
	}
	return c.tlsServer.HandshakeComplete()
}

func (c *ServerPeerConnection) TLSConnectionState() tls.ConnectionState {
	if c == nil || c.tlsServer == nil {
		return tls.ConnectionState{}
	}
	return c.tlsServer.ConnectionState()
}

func (c *ServerPeerConnection) TLSEnabled() bool {
	return c != nil && c.tlsServer != nil
}

func (c *ServerPeerConnection) TLSReadSecret(level tls.QUICEncryptionLevel) ([]byte, uint16, bool) {
	if c == nil || c.tlsServer == nil {
		return nil, 0, false
	}
	secret, ok := c.tlsServer.readSecrets[level]
	if !ok || len(secret) == 0 {
		return nil, 0, false
	}
	return append([]byte(nil), secret...), c.tlsServer.readSecretSuites[level], true
}

func (c *ServerPeerConnection) TLSWriteSecret(level tls.QUICEncryptionLevel) ([]byte, uint16, bool) {
	if c == nil || c.tlsServer == nil {
		return nil, 0, false
	}
	secret, ok := c.tlsServer.writeSecrets[level]
	if !ok || len(secret) == 0 {
		return nil, 0, false
	}
	return append([]byte(nil), secret...), c.tlsServer.writeSecretSuites[level], true
}

func (c *ServerPeerConnection) HandleBusinessPacket(ctx context.Context, payload []byte, handler func(context.Context, *core.Request) (*core.Response, error)) (ServerConnSnapshot, error) {
	if c == nil || c.server == nil {
		return ServerConnSnapshot{}, ErrServerPeerConnectionUnavailable
	}
	if handler == nil {
		return ServerConnSnapshot{}, ErrServerPeerConnectionUnavailable
	}
	if consumed, snapshot, err := c.handleTLSPacket(ctx, payload); consumed || err != nil {
		return snapshot, err
	}
	return c.server.HandlePacket(ctx, payload, ServerRequestHandlerFunc(handler))
}

func (c *ServerPeerConnection) handleTLSPacket(ctx context.Context, payload []byte) (bool, ServerConnSnapshot, error) {
	if c == nil || c.server == nil || c.tlsServer == nil || len(payload) == 0 {
		return false, ServerConnSnapshot{}, nil
	}
	shortHeaderDestinationConnectionIDLength := DefaultShortHeaderDestinationConnectionIDLength
	if c.server != nil && c.server.shortHeaderDestinationConnectionIDLength > 0 {
		shortHeaderDestinationConnectionIDLength = c.server.shortHeaderDestinationConnectionIDLength
	}
	header, err := ParseQUICPacketHeader(payload, shortHeaderDestinationConnectionIDLength)
	if err != nil {
		if errors.Is(err, ErrNotQUICPacket) || isPartialData(err) {
			return false, ServerConnSnapshot{}, nil
		}
		return true, ServerConnSnapshot{}, err
	}
	level, ok := QUICPacketTypeEncryptionLevel(header.Type)
	if !ok {
		return false, ServerConnSnapshot{}, nil
	}
	if header.PayloadOffset > len(payload) {
		return true, ServerConnSnapshot{}, io.ErrUnexpectedEOF
	}
	packetPayload := payload[header.PayloadOffset:]
	space, tracked := c.server.observeQUICPacketHeader(header)
	if tracked && header.Type != QUICPacketTypeOneRTT {
		if closePeer, err := c.server.observeNonApplicationPacket(space, packetPayload); err != nil {
			return true, c.server.Snapshot(), err
		} else if closePeer {
			return true, c.server.Snapshot(), nil
		}
	}
	if header.Type == QUICPacketTypeOneRTT && c.TLSHandshakeComplete() {
		return false, ServerConnSnapshot{}, nil
	}
	if _, err := ParseQUICCryptoFrames(packetPayload); err != nil {
		if header.Type == QUICPacketTypeOneRTT {
			return false, ServerConnSnapshot{}, nil
		}
		return true, ServerConnSnapshot{}, err
	}
	if err := c.StartTLS(ctx); err != nil {
		return true, ServerConnSnapshot{}, err
	}
	if err := c.tlsServer.HandleCryptoFrames(level, packetPayload); err != nil {
		return true, c.server.Snapshot(), err
	}
	return true, c.server.Snapshot(), nil
}
