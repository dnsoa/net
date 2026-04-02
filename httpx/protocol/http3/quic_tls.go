package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
)

var ErrQUICTLSUnavailable = errors.New("http3 quic tls handshake is not configured")
var ErrQUICTLSALPNNegotiation = errors.New("http3 quic tls alpn negotiation failed")

const HTTP3ALPN = "h3"

type QUICTLSHandshake struct {
	conn                 *tls.QUICConn
	localTransportParams []byte
	peerTransportParams  []byte
	pendingWrites        map[tls.QUICEncryptionLevel][]byte
	readOffsets          map[tls.QUICEncryptionLevel]uint64
	writeOffsets         map[tls.QUICEncryptionLevel]uint64
	handshakeComplete    bool
	lastError            error
	started              bool
	transportParamsSet   bool
	readSecrets          map[tls.QUICEncryptionLevel][]byte
	writeSecrets         map[tls.QUICEncryptionLevel][]byte
	readSecretSuites     map[tls.QUICEncryptionLevel]uint16
	writeSecretSuites    map[tls.QUICEncryptionLevel]uint16
}

func NewQUICTLSServerHandshake(config *tls.Config, transportParams []byte) (*QUICTLSHandshake, error) {
	if config == nil {
		return nil, ErrQUICTLSUnavailable
	}
	clone := config.Clone()
	clone.NextProtos = normalizeHTTP3NextProtos(clone.NextProtos)
	if clone.MinVersion < tls.VersionTLS13 {
		clone.MinVersion = tls.VersionTLS13
	}
	if clone.MaxVersion != 0 && clone.MaxVersion < tls.VersionTLS13 {
		clone.MaxVersion = tls.VersionTLS13
	}
	return newQUICTLSHandshake(tls.QUICServer(&tls.QUICConfig{TLSConfig: clone}), transportParams)
}

func NewQUICTLSClientHandshake(config *tls.Config, transportParams []byte) (*QUICTLSHandshake, error) {
	if config == nil {
		return nil, ErrQUICTLSUnavailable
	}
	clone := config.Clone()
	clone.NextProtos = normalizeHTTP3NextProtos(clone.NextProtos)
	if clone.MinVersion < tls.VersionTLS13 {
		clone.MinVersion = tls.VersionTLS13
	}
	if clone.MaxVersion != 0 && clone.MaxVersion < tls.VersionTLS13 {
		clone.MaxVersion = tls.VersionTLS13
	}
	return newQUICTLSHandshake(tls.QUICClient(&tls.QUICConfig{TLSConfig: clone}), transportParams)
}

func newQUICTLSHandshake(conn *tls.QUICConn, transportParams []byte) (*QUICTLSHandshake, error) {
	if conn == nil {
		return nil, ErrQUICTLSUnavailable
	}
	return &QUICTLSHandshake{
		conn:                 conn,
		localTransportParams: append([]byte(nil), transportParams...),
		pendingWrites:        make(map[tls.QUICEncryptionLevel][]byte),
		readOffsets:          make(map[tls.QUICEncryptionLevel]uint64),
		writeOffsets:         make(map[tls.QUICEncryptionLevel]uint64),
		readSecrets:          make(map[tls.QUICEncryptionLevel][]byte),
		writeSecrets:         make(map[tls.QUICEncryptionLevel][]byte),
		readSecretSuites:     make(map[tls.QUICEncryptionLevel]uint16),
		writeSecretSuites:    make(map[tls.QUICEncryptionLevel]uint16),
	}, nil
}

func (h *QUICTLSHandshake) Start(ctx context.Context) error {
	if h == nil || h.conn == nil {
		return ErrQUICTLSUnavailable
	}
	if h.started {
		return nil
	}
	if len(h.localTransportParams) > 0 {
		h.conn.SetTransportParameters(h.localTransportParams)
		h.transportParamsSet = true
	}
	h.started = true
	if err := h.conn.Start(ctx); err != nil {
		return err
	}
	return h.drainEvents()
}

func (h *QUICTLSHandshake) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	if h == nil || h.conn == nil {
		return ErrQUICTLSUnavailable
	}
	if err := h.conn.HandleData(level, data); err != nil {
		return err
	}
	return h.drainEvents()
}

func (h *QUICTLSHandshake) HandleCryptoFrames(level tls.QUICEncryptionLevel, payload []byte) error {
	frames, err := ParseQUICCryptoFrames(payload)
	if err != nil {
		return err
	}
	if len(frames) == 0 {
		return nil
	}
	expectedOffset := h.readOffsets[level]
	var cryptoData []byte
	for _, frame := range frames {
		if frame.Offset != expectedOffset {
			return fmt.Errorf("http3 quic tls crypto frame out of order: level=%s expected=%d got=%d", level, expectedOffset, frame.Offset)
		}
		cryptoData = append(cryptoData, frame.Data...)
		expectedOffset += uint64(len(frame.Data))
	}
	h.readOffsets[level] = expectedOffset
	return h.HandleData(level, cryptoData)
}

func (h *QUICTLSHandshake) DrainCryptoFrames(level tls.QUICEncryptionLevel) ([]byte, error) {
	if h == nil {
		return nil, ErrQUICTLSUnavailable
	}
	data := h.pendingWrites[level]
	if len(data) == 0 {
		return nil, nil
	}
	delete(h.pendingWrites, level)
	frame, err := AppendQUICCryptoFrame(nil, h.writeOffsets[level], data)
	if err != nil {
		return nil, err
	}
	h.writeOffsets[level] += uint64(len(data))
	return frame, nil
}

func (h *QUICTLSHandshake) HandshakeComplete() bool {
	if h == nil {
		return false
	}
	return h.handshakeComplete
}

func (h *QUICTLSHandshake) ConnectionState() tls.ConnectionState {
	if h == nil || h.conn == nil {
		return tls.ConnectionState{}
	}
	return h.conn.ConnectionState()
}

func (h *QUICTLSHandshake) PeerTransportParameters() []byte {
	if h == nil {
		return nil
	}
	return append([]byte(nil), h.peerTransportParams...)
}

func (h *QUICTLSHandshake) LastError() error {
	if h == nil {
		return nil
	}
	return h.lastError
}

func (h *QUICTLSHandshake) drainEvents() error {
	for {
		event := h.conn.NextEvent()
		switch event.Kind {
		case tls.QUICNoEvent:
			return h.lastError
		case tls.QUICSetReadSecret:
			h.readSecrets[event.Level] = append([]byte(nil), event.Data...)
			h.readSecretSuites[event.Level] = event.Suite
		case tls.QUICSetWriteSecret:
			h.writeSecrets[event.Level] = append([]byte(nil), event.Data...)
			h.writeSecretSuites[event.Level] = event.Suite
		case tls.QUICWriteData:
			h.pendingWrites[event.Level] = append(h.pendingWrites[event.Level], event.Data...)
		case tls.QUICTransportParameters:
			h.peerTransportParams = append(h.peerTransportParams[:0], event.Data...)
		case tls.QUICTransportParametersRequired:
			if !h.transportParamsSet {
				h.conn.SetTransportParameters(h.localTransportParams)
				h.transportParamsSet = true
			}
		case tls.QUICHandshakeDone:
			if h.conn.ConnectionState().NegotiatedProtocol != HTTP3ALPN {
				h.lastError = fmt.Errorf("%w: negotiated=%q", ErrQUICTLSALPNNegotiation, h.conn.ConnectionState().NegotiatedProtocol)
				return h.lastError
			}
			h.handshakeComplete = true
		}
	}
}

func normalizeHTTP3NextProtos(nextProtos []string) []string {
	seen := make(map[string]struct{}, len(nextProtos)+1)
	normalized := make([]string, 0, len(nextProtos)+1)
	normalized = append(normalized, HTTP3ALPN)
	seen[HTTP3ALPN] = struct{}{}
	for _, proto := range nextProtos {
		if proto == "" {
			continue
		}
		if _, ok := seen[proto]; ok {
			continue
		}
		seen[proto] = struct{}{}
		normalized = append(normalized, proto)
	}
	return normalized
}

func QUICPacketTypeEncryptionLevel(packetType QUICPacketType) (tls.QUICEncryptionLevel, bool) {
	switch packetType {
	case QUICPacketTypeInitial:
		return tls.QUICEncryptionLevelInitial, true
	case QUICPacketTypeZeroRTT:
		return tls.QUICEncryptionLevelEarly, true
	case QUICPacketTypeHandshake:
		return tls.QUICEncryptionLevelHandshake, true
	case QUICPacketTypeOneRTT:
		return tls.QUICEncryptionLevelApplication, true
	default:
		return 0, false
	}
}
