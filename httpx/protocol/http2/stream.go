package http2

import (
	"bytes"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"

	"github.com/dnsoa/net/httpx/core"
)

type StreamState uint8

const (
	StreamIdle StreamState = iota
	StreamReservedLocal
	StreamReservedRemote
	StreamOpen
	StreamHalfClosedLocal
	StreamHalfClosedRemote
	StreamClosed
)

type Stream struct {
	ID         uint32
	State      StreamState
	SendWindow int32
	RecvWindow int32
}

type DecodedHeaderBlock struct {
	StreamID  uint32
	EndStream bool
	Fields    []hpack.HeaderField
}

type pendingHeaderBlock struct {
	streamID  uint32
	endStream bool
	payload   []byte
}

type StreamManager struct {
	IsClient       bool
	NextStreamID   uint32
	LocalSettings  ConnectionSettings
	PeerSettings   ConnectionSettings
	Streams        map[uint32]*Stream
	LastRemoteSeen uint32
	encodeBuf      bytes.Buffer
	encoder        *hpack.Encoder
	decoder        *hpack.Decoder
	decodedFields  []hpack.HeaderField
	pendingHeaders *pendingHeaderBlock
}

func NewStreamManager(isClient bool, localSettings, peerSettings ConnectionSettings) *StreamManager {
	startID := uint32(1)
	if !isClient {
		startID = 2
	}
	mgr := &StreamManager{
		IsClient:      isClient,
		NextStreamID:  startID,
		LocalSettings: localSettings,
		PeerSettings:  peerSettings,
		Streams:       make(map[uint32]*Stream),
	}
	mgr.encoder = hpack.NewEncoder(&mgr.encodeBuf)
	mgr.encoder.SetMaxDynamicTableSizeLimit(peerSettings.HeaderTableSize)
	mgr.decoder = hpack.NewDecoder(localSettings.HeaderTableSize, func(field hpack.HeaderField) {
		mgr.decodedFields = append(mgr.decodedFields, field)
	})
	return mgr
}

func (m *StreamManager) OpenStream() (*Stream, error) {
	if uint32(len(m.Streams)) >= m.PeerSettings.MaxConcurrentStreams && m.PeerSettings.MaxConcurrentStreams != 0 {
		return nil, errors.New("http2 max concurrent streams exceeded")
	}
	id := m.NextStreamID
	m.NextStreamID += 2
	stream := &Stream{
		ID:         id,
		State:      StreamOpen,
		SendWindow: int32(m.PeerSettings.InitialWindowSize),
		RecvWindow: int32(m.LocalSettings.InitialWindowSize),
	}
	m.Streams[id] = stream
	return stream, nil
}

func (m *StreamManager) Get(id uint32) (*Stream, bool) {
	stream, ok := m.Streams[id]
	return stream, ok
}

func (m *StreamManager) ApplyReceivedFrame(frame Frame) error {
	return m.applyFrame(frame, true)
}

func (m *StreamManager) ApplySentFrame(frame Frame) error {
	return m.applyFrame(frame, false)
}

func (m *StreamManager) BuildHeadersFrame(streamID uint32, payload []byte, endStream bool, endHeaders bool) Frame {
	flags := uint8(0)
	if endStream {
		flags |= FlagEndStream
	}
	if endHeaders {
		flags |= FlagEndHeaders
	}
	return Frame{
		Header: FrameHeader{
			Length:   uint32(len(payload)),
			Type:     FrameHeaders,
			Flags:    flags,
			StreamID: streamID,
		},
		Payload: payload,
	}
}

func (m *StreamManager) BuildRequestHeaderFrames(streamID uint32, req *core.Request, endStream bool) ([]Frame, error) {
	block, err := m.encodeRequestHeaderBlock(req)
	if err != nil {
		return nil, err
	}
	return m.buildHeaderBlockFrames(streamID, block, endStream), nil
}

func (m *StreamManager) BuildResponseHeaderFrames(streamID uint32, resp *core.Response, endStream bool) ([]Frame, error) {
	block, err := m.encodeResponseHeaderBlock(resp)
	if err != nil {
		return nil, err
	}
	return m.buildHeaderBlockFrames(streamID, block, endStream), nil
}

func (m *StreamManager) BuildTrailerFrames(streamID uint32, trailers *core.Headers, endStream bool) ([]Frame, error) {
	block, err := m.encodeTrailerHeaderBlock(trailers)
	if err != nil {
		return nil, err
	}
	return m.buildHeaderBlockFrames(streamID, block, endStream), nil
}

func (m *StreamManager) ReceiveHeaderBlockFrame(frame Frame) (*DecodedHeaderBlock, error) {
	switch frame.Header.Type {
	case FrameHeaders:
		if m.pendingHeaders != nil {
			return nil, errors.New("http2 interleaved header block fragments")
		}
		if err := m.ApplyReceivedFrame(frame); err != nil {
			return nil, err
		}
		// Strip PRIORITY and PADDED prefix per RFC 7540 §6.2.
		payload := frame.Payload
		if frame.Header.Flags&FlagPadded != 0 {
			if len(payload) == 0 {
				return nil, errors.New("http2 padded headers frame with empty payload")
			}
			padLen := int(payload[0])
			payload = payload[1:]
			if padLen > len(payload) {
				return nil, errors.New("http2 headers frame padding exceeds payload")
			}
			payload = payload[:len(payload)-padLen]
		}
		if frame.Header.Flags&FlagPriority != 0 {
			if len(payload) < 5 {
				return nil, errors.New("http2 priority headers frame with short payload")
			}
			payload = payload[5:] // skip E(1bit)+StreamDependency(31bits)+Weight(8bits)
		}
		pending := &pendingHeaderBlock{
			streamID:  frame.Header.StreamID,
			endStream: frame.Header.Flags&FlagEndStream != 0,
			payload:   append([]byte(nil), payload...),
		}
		if frame.Header.Flags&FlagEndHeaders != 0 {
			return m.decodeHeaderBlock(pending)
		}
		m.pendingHeaders = pending
		return nil, nil
	case FrameContinuation:
		if m.pendingHeaders == nil {
			return nil, errors.New("http2 unexpected continuation frame")
		}
		if frame.Header.StreamID != m.pendingHeaders.streamID {
			return nil, errors.New("http2 continuation stream mismatch")
		}
		m.pendingHeaders.payload = append(m.pendingHeaders.payload, frame.Payload...)
		if frame.Header.Flags&FlagEndHeaders != 0 {
			decoded, err := m.decodeHeaderBlock(m.pendingHeaders)
			m.pendingHeaders = nil
			return decoded, err
		}
		return nil, nil
	default:
		return nil, errors.New("http2 frame is not a header block fragment")
	}
}

func (m *StreamManager) DecodeRequestHeaderBlock(fields []hpack.HeaderField) (*core.Request, error) {
	var method string
	var scheme string
	var authority string
	var path string
	req := core.AcquireRequest()
	req.Version = core.VersionHTTP2
	for _, field := range fields {
		switch field.Name {
		case ":method":
			method = field.Value
		case ":scheme":
			scheme = field.Value
		case ":authority":
			authority = field.Value
		case ":path":
			path = field.Value
		default:
			req.Headers.AppendString(field.Name, field.Value)
		}
	}
	parsedMethod, ok := core.ParseMethodBytes([]byte(method))
	if !ok {
		core.ReleaseRequest(req)
		return nil, errors.New("http2 unsupported request method")
	}
	req.Method = parsedMethod
	if path == "" {
		path = "/"
	}
	if scheme == "" {
		scheme = "http"
	}
	uri := path
	if authority != "" {
		uri = scheme + "://" + authority + path
	}
	if err := req.URI.ParseString(uri); err != nil {
		core.ReleaseRequest(req)
		return nil, err
	}
	if authority != "" && req.Headers.Get("Host") == nil {
		req.Headers.Set(core.HeaderHost, []byte(authority))
	}
	return req, nil
}

func (m *StreamManager) DecodeResponseHeaderBlock(fields []hpack.HeaderField) (*core.Response, error) {
	resp := core.AcquireResponse()
	resp.Version = core.VersionHTTP2
	for _, field := range fields {
		if field.Name == ":status" {
			code, err := strconv.Atoi(field.Value)
			if err != nil {
				core.ReleaseResponse(resp)
				return nil, errors.New("http2 invalid response status")
			}
			resp.Status = core.NewStatus(code)
			continue
		}
		resp.Headers.AppendString(field.Name, field.Value)
	}
	return resp, nil
}

func (m *StreamManager) DecodeTrailerHeaderBlock(fields []hpack.HeaderField) (core.Headers, error) {
	trailers := core.NewHeaders()
	for _, field := range fields {
		if strings.HasPrefix(field.Name, ":") {
			trailers.Reset()
			return core.Headers{}, errors.New("http2 trailers must not contain pseudo headers")
		}
		trailers.AppendString(field.Name, field.Value)
	}
	return trailers, nil
}

func (m *StreamManager) BuildDataFrames(streamID uint32, payload []byte, endStream bool) ([]Frame, error) {
	stream, ok := m.Streams[streamID]
	if !ok {
		return nil, errors.New("http2 stream not found")
	}
	if stream.State == StreamHalfClosedLocal || stream.State == StreamClosed {
		return nil, errors.New("http2 stream closed for local sending")
	}
	if stream.SendWindow < int32(len(payload)) {
		return nil, errors.New("http2 send window exceeded")
	}
	maxFrame := int(m.PeerSettings.MaxFrameSize)
	if maxFrame <= 0 {
		maxFrame = 16384
	}
	frames := make([]Frame, 0, (len(payload)+maxFrame-1)/maxFrame)
	for offset := 0; offset < len(payload); offset += maxFrame {
		end := offset + maxFrame
		if end > len(payload) {
			end = len(payload)
		}
		flags := uint8(0)
		if end == len(payload) && endStream {
			flags |= FlagEndStream
		}
		chunk := payload[offset:end]
		frames = append(frames, Frame{
			Header: FrameHeader{
				Length:   uint32(len(chunk)),
				Type:     FrameData,
				Flags:    flags,
				StreamID: streamID,
			},
			Payload: chunk,
		})
	}
	stream.SendWindow -= int32(len(payload))
	if endStream {
		transitionCloseByLocal(stream)
	}
	return frames, nil
}

func (m *StreamManager) encodeRequestHeaderBlock(req *core.Request) ([]byte, error) {
	m.encodeBuf.Reset()
	fields := make([]hpack.HeaderField, 0, req.Headers.Count()+4)
	fields = append(fields,
		hpack.HeaderField{Name: ":method", Value: req.Method.String()},
		hpack.HeaderField{Name: ":scheme", Value: requestScheme(req)},
		hpack.HeaderField{Name: ":authority", Value: requestAuthority(req)},
		hpack.HeaderField{Name: ":path", Value: string(req.URI.RequestTarget(nil))},
	)
	for _, entry := range req.Headers.Entries() {
		name := strings.ToLower(string(entry.Name))
		if shouldSkipHTTP2Header(name) {
			continue
		}
		fields = append(fields, hpack.HeaderField{Name: name, Value: string(entry.Value)})
	}
	for _, field := range fields {
		if err := m.encoder.WriteField(field); err != nil {
			return nil, err
		}
	}
	return append([]byte(nil), m.encodeBuf.Bytes()...), nil
}

func (m *StreamManager) encodeResponseHeaderBlock(resp *core.Response) ([]byte, error) {
	m.encodeBuf.Reset()
	fields := make([]hpack.HeaderField, 0, resp.Headers.Count()+1)
	fields = append(fields, hpack.HeaderField{Name: ":status", Value: strconv.Itoa(resp.Status.Code)})
	for _, entry := range resp.Headers.Entries() {
		name := strings.ToLower(string(entry.Name))
		if shouldSkipHTTP2Header(name) {
			continue
		}
		fields = append(fields, hpack.HeaderField{Name: name, Value: string(entry.Value)})
	}
	for _, field := range fields {
		if err := m.encoder.WriteField(field); err != nil {
			return nil, err
		}
	}
	return append([]byte(nil), m.encodeBuf.Bytes()...), nil
}

func (m *StreamManager) encodeTrailerHeaderBlock(trailers *core.Headers) ([]byte, error) {
	m.encodeBuf.Reset()
	if trailers == nil || trailers.Count() == 0 {
		return nil, nil
	}
	for _, entry := range trailers.Entries() {
		name := strings.ToLower(string(entry.Name))
		if shouldSkipHTTP2Header(name) {
			return nil, errors.New("http2 trailers contain disallowed header")
		}
		if err := m.encoder.WriteField(hpack.HeaderField{Name: name, Value: string(entry.Value)}); err != nil {
			return nil, err
		}
	}
	return append([]byte(nil), m.encodeBuf.Bytes()...), nil
}

func (m *StreamManager) buildHeaderBlockFrames(streamID uint32, block []byte, endStream bool) []Frame {
	maxFrame := int(m.PeerSettings.MaxFrameSize)
	if maxFrame <= 0 {
		maxFrame = 16384
	}
	if len(block) == 0 {
		return []Frame{m.BuildHeadersFrame(streamID, nil, endStream, true)}
	}
	frames := make([]Frame, 0, (len(block)+maxFrame-1)/maxFrame)
	for offset := 0; offset < len(block); offset += maxFrame {
		end := offset + maxFrame
		if end > len(block) {
			end = len(block)
		}
		flags := uint8(0)
		if offset == 0 && endStream {
			flags |= FlagEndStream
		}
		if end == len(block) {
			flags |= FlagEndHeaders
		}
		frameType := FrameHeaders
		if offset > 0 {
			frameType = FrameContinuation
		}
		chunk := block[offset:end]
		frames = append(frames, Frame{
			Header: FrameHeader{
				Length:   uint32(len(chunk)),
				Type:     frameType,
				Flags:    flags,
				StreamID: streamID,
			},
			Payload: chunk,
		})
	}
	return frames
}

func (m *StreamManager) decodeHeaderBlock(pending *pendingHeaderBlock) (*DecodedHeaderBlock, error) {
	fields, err := m.decoder.DecodeFull(pending.payload)
	if err != nil {
		return nil, err
	}
	return &DecodedHeaderBlock{
		StreamID:  pending.streamID,
		EndStream: pending.endStream,
		Fields:    append([]hpack.HeaderField(nil), fields...),
	}, nil
}

func (m *StreamManager) applyFrame(frame Frame, received bool) error {
	if frame.Header.StreamID == 0 {
		return m.applyConnectionFrame(frame, received)
	}
	stream, err := m.ensureStream(frame, received)
	if err != nil {
		return err
	}
	senderIsRemote := received
	switch frame.Header.Type {
	case FrameHeaders:
		if !streamAllowsSender(stream.State, senderIsRemote) {
			return errors.New("http2 headers on closed stream side")
		}
		if frame.Header.Flags&FlagEndStream != 0 {
			if senderIsRemote {
				transitionCloseByRemote(stream)
			} else {
				transitionCloseByLocal(stream)
			}
		}
	case FrameData:
		if !streamAllowsSender(stream.State, senderIsRemote) {
			return errors.New("http2 data on closed stream side")
		}
		if senderIsRemote {
			stream.RecvWindow -= int32(len(frame.Payload))
			if stream.RecvWindow < 0 {
				return errors.New("http2 receive window exceeded")
			}
		} else {
			stream.SendWindow -= int32(len(frame.Payload))
			if stream.SendWindow < 0 {
				return errors.New("http2 send window exceeded")
			}
		}
		if frame.Header.Flags&FlagEndStream != 0 {
			if senderIsRemote {
				transitionCloseByRemote(stream)
			} else {
				transitionCloseByLocal(stream)
			}
		}
	case FrameRSTStream:
		stream.State = StreamClosed
	case FrameWindowUpdate:
		if len(frame.Payload) != 4 {
			return errors.New("http2 invalid window update length")
		}
		increment := int32(uint32(frame.Payload[0]&0x7F)<<24 | uint32(frame.Payload[1])<<16 | uint32(frame.Payload[2])<<8 | uint32(frame.Payload[3]))
		if increment <= 0 {
			return errors.New("http2 invalid window increment")
		}
		if senderIsRemote {
			stream.SendWindow += increment
		} else {
			stream.RecvWindow += increment
		}
	}
	if stream.State == StreamClosed {
		delete(m.Streams, stream.ID)
	}
	return nil
}

func (m *StreamManager) applyConnectionFrame(frame Frame, received bool) error {
	if frame.Header.Type != FrameWindowUpdate {
		return nil
	}
	if len(frame.Payload) != 4 {
		return errors.New("http2 invalid connection window update length")
	}
	_ = received
	return nil
}

func (m *StreamManager) ensureStream(frame Frame, received bool) (*Stream, error) {
	if stream, ok := m.Streams[frame.Header.StreamID]; ok {
		return stream, nil
	}
	if frame.Header.Type != FrameHeaders {
		return nil, errors.New("http2 frame for unknown stream")
	}
	if m.isLocalStreamID(frame.Header.StreamID) == received {
		return nil, errors.New("http2 invalid stream initiator")
	}
	if frame.Header.StreamID <= m.LastRemoteSeen {
		return nil, errors.New("http2 remote stream id regression")
	}
	m.LastRemoteSeen = frame.Header.StreamID
	stream := &Stream{
		ID:         frame.Header.StreamID,
		State:      StreamOpen,
		SendWindow: int32(m.PeerSettings.InitialWindowSize),
		RecvWindow: int32(m.LocalSettings.InitialWindowSize),
	}
	m.Streams[stream.ID] = stream
	return stream, nil
}

func (m *StreamManager) isLocalStreamID(id uint32) bool {
	if m.IsClient {
		return id%2 == 1
	}
	return id%2 == 0
}

func streamAllowsSender(state StreamState, senderIsRemote bool) bool {
	switch state {
	case StreamOpen:
		return true
	case StreamHalfClosedLocal:
		return senderIsRemote
	case StreamHalfClosedRemote:
		return !senderIsRemote
	default:
		return false
	}
}

func transitionCloseByLocal(stream *Stream) {
	switch stream.State {
	case StreamOpen:
		stream.State = StreamHalfClosedLocal
	case StreamHalfClosedRemote:
		stream.State = StreamClosed
	}
}

func transitionCloseByRemote(stream *Stream) {
	switch stream.State {
	case StreamOpen:
		stream.State = StreamHalfClosedRemote
	case StreamHalfClosedLocal:
		stream.State = StreamClosed
	}
}

func requestScheme(req *core.Request) string {
	if len(req.URI.Scheme) > 0 {
		return string(req.URI.Scheme)
	}
	if req.URI.IsTLS() {
		return "https"
	}
	return "http"
}

func requestAuthority(req *core.Request) string {
	if len(req.URI.Host) == 0 {
		if host := req.Headers.Get("Host"); host != nil {
			return string(host)
		}
		return ""
	}
	authority := string(req.URI.Host)
	if req.URI.HasPort {
		authority += ":" + strconv.Itoa(int(req.URI.Port))
	}
	return authority
}

func shouldSkipHTTP2Header(name string) bool {
	switch name {
	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "host":
		return true
	default:
		return strings.HasPrefix(name, ":")
	}
}
