package http2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/dnsoa/net/httpx/core"
)

// Stream state constants for atomic state tracking.
const (
	stateOpen             int32 = 0
	stateHalfClosedRemote int32 = 1
	stateHalfClosedLocal  int32 = 2
	stateClosed           int32 = 3
)

// dataChCapacity is the hard upper limit for per-stream dataCh buffer.
// Default: ceil(65535/16384) + 1 = 5, hard cap 8 (don't trust peer SETTINGS).
const dataChCapacity = 8

var (
	// errStreamClosed is returned when writing to a closed stream.
	errStreamClosed = errors.New("http2: stream closed")
	// errStreamReset is returned when the peer sends RST_STREAM.
	errStreamReset = errors.New("http2: stream reset by peer")
	// errDataOverflow is returned on dataCh overflow (flow control violation).
	errDataOverflow = errors.New("http2: flow control error")
)

// streamState tracks per-stream concurrent state for the single-reader multi-writer model.
type streamState struct {
	id         uint32
	state      atomic.Int32 // stateOpen / stateHalfClosedRemote / stateHalfClosedLocal / stateClosed
	dataCh     chan []byte  // readLoop → streamReader
	errCh      chan error   // RST/GOAWAY notification
	sendWindow atomic.Int32
	windowCond *sync.Cond // wake blocked streamWriter on WINDOW_UPDATE
	closed     atomic.Bool
	trailers   atomic.Pointer[core.Headers] // request trailers (set by readLoop on END_STREAM HEADERS)
	termErr    atomic.Pointer[error]        // terminal error: checked before EOF in streamReader.Read
}

// dispatchedRequest is sent from readLoop to ReadRequest / ReadStreamRequest callers.
type dispatchedRequest struct {
	streamID uint32
	request  *core.Request
	bodyCh   chan []byte // nil when END_STREAM received with HEADERS (no body)
	errCh    chan error
	ss       *streamState // for reading trailers after body is consumed
}

// streamReader reads data from a stream's dataCh, implementing io.Reader.
// Receive-side WINDOW_UPDATE is bound to Read() consumption — not to readLoop receipt.
type streamReader struct {
	dataCh            chan []byte
	errCh             chan error
	buf               []byte
	bufOff            int
	session           *Session
	streamID          uint32
	recvWindow        int32
	windowMu          sync.Mutex
	initialWindowSize int32
	ss                *streamState // for reading trailers after body is consumed
}

// Trailers returns the request trailers, if any were received.
// Must be called after the body has been fully read (io.EOF received from Read).
func (r *streamReader) Trailers() *core.Headers {
	if r.ss == nil {
		return nil
	}
	return r.ss.trailers.Load()
}

func (r *streamReader) Read(p []byte) (int, error) {
	if r.dataCh == nil {
		return 0, io.EOF
	}
	for {
		if r.bufOff < len(r.buf) {
			n := copy(p, r.buf[r.bufOff:])
			r.bufOff += n
			r.maybeSendWindowUpdate(n)
			return n, nil
		}
		select {
		case data, ok := <-r.dataCh:
			if !ok {
				// dataCh closed — check for terminal error before returning EOF.
				if r.ss != nil {
					if pErr := r.ss.termErr.Load(); pErr != nil {
						return 0, *pErr
					}
				}
				return 0, io.EOF
			}
			r.buf = data
			r.bufOff = 0
		case err := <-r.errCh:
			return 0, err
		}
	}
}

func (r *streamReader) maybeSendWindowUpdate(consumed int) {
	r.windowMu.Lock()
	r.recvWindow -= int32(consumed)
	if r.recvWindow <= r.initialWindowSize/2 {
		increment := r.initialWindowSize - r.recvWindow
		r.recvWindow = r.initialWindowSize
		r.windowMu.Unlock()
		r.session.writeMu.Lock()
		r.session.writeWindowUpdate(r.streamID, uint32(increment))
		r.session.writeMu.Unlock()
		return
	}
	r.windowMu.Unlock()
}

// streamWriter writes DATA frames to a stream with flow control, implementing io.WriteCloser.
type streamWriter struct {
	session  *Session
	streamID uint32
	ss       *streamState
}

func (w *streamWriter) Write(p []byte) (int, error) {
	if w.ss.closed.Load() {
		return 0, errStreamClosed
	}
	written := 0
	for written < len(p) {
		if w.ss.closed.Load() {
			return written, errStreamClosed
		}

		// Wait for stream-level send window.
		for w.ss.sendWindow.Load() <= 0 {
			w.ss.windowCond.L.Lock()
			w.ss.windowCond.Wait()
			w.ss.windowCond.L.Unlock()
			if w.ss.closed.Load() {
				return written, errStreamClosed
			}
		}

		// Wait for connection-level send window (cannot busy-wait).
		for w.session.connSendWindow.Load() <= 0 {
			w.session.connWindowCond.L.Lock()
			w.session.connWindowCond.Wait()
			w.session.connWindowCond.L.Unlock()
			if w.ss.closed.Load() {
				return written, errStreamClosed
			}
		}

		maxFrame := int(w.session.streams.PeerSettings.MaxFrameSize)
		if maxFrame <= 0 {
			maxFrame = 16384
		}

		// Atomically reserve both stream and connection windows via CAS.
		// This prevents concurrent writers from over-subscribing based on stale values.
		chunk := w.reserveWindow(len(p)-written, maxFrame)
		if chunk <= 0 {
			continue // windows consumed by another writer; re-wait
		}

		// Write frame under writeMu to protect frame boundaries + HPACK encoder.
		w.session.writeMu.Lock()
		err := w.session.conn.WriteFrame(FrameHeader{
			Length:   uint32(chunk),
			Type:     FrameData,
			StreamID: w.streamID,
		}, p[written:written+chunk])
		w.session.writeMu.Unlock()
		if err != nil {
			// Return reserved window on write failure.
			w.ss.sendWindow.Add(int32(chunk))
			w.session.connSendWindow.Add(int32(chunk))
			return written, err
		}

		written += chunk
	}
	return written, nil
}

// reserveWindow atomically reserves the minimum of (remaining, streamAvail, connAvail, maxFrame)
// from both stream and connection windows using a CAS loop.
// Returns 0 if either window was consumed by a concurrent writer (caller should re-wait).
func (w *streamWriter) reserveWindow(remaining, maxFrame int) int {
	for {
		streamAvail := int(w.ss.sendWindow.Load())
		connAvail := int(w.session.connSendWindow.Load())
		if streamAvail <= 0 || connAvail <= 0 {
			return 0
		}
		chunk := min(min(min(remaining, streamAvail), connAvail), maxFrame)
		if chunk <= 0 {
			return 0
		}
		// Atomically deduct from stream window.
		if !w.ss.sendWindow.CompareAndSwap(int32(streamAvail), int32(streamAvail-chunk)) {
			continue
		}
		// Atomically deduct from connection window.
		if !w.session.connSendWindow.CompareAndSwap(int32(connAvail), int32(connAvail-chunk)) {
			// Rollback stream window.
			w.ss.sendWindow.Add(int32(chunk))
			continue
		}
		return chunk
	}
}

func (w *streamWriter) Close() error {
	w.session.writeMu.Lock()
	err := w.session.conn.WriteFrame(FrameHeader{
		Type:     FrameData,
		Flags:    FlagEndStream,
		StreamID: w.streamID,
	}, nil)
	w.session.writeMu.Unlock()
	if err != nil {
		return err
	}
	if w.ss.state.CompareAndSwap(stateOpen, stateHalfClosedLocal) {
		// open → half-closed (local)
	} else if w.ss.state.CompareAndSwap(stateHalfClosedRemote, stateClosed) {
		w.session.unregisterStream(w.streamID)
	}
	return nil
}

// Session manages an HTTP/2 connection with single-reader multi-writer concurrency.
type Session struct {
	conn             *Conn
	streams          *StreamManager
	maxReadFrameSize int

	// Concurrency control
	writeMu      sync.Mutex
	readLoopOnce sync.Once
	readLoopDone chan struct{}
	readLoopErr  error

	// Active stream registry (replaces incomingRequests map)
	activeStreams map[uint32]*streamState
	streamMu      sync.Mutex

	// Connection-level flow control
	connSendWindow atomic.Int32
	connRecvWindow atomic.Int32
	connWindowCond *sync.Cond

	// Request dispatch channel
	dispatchCh chan dispatchedRequest
}

// NewServerSession creates an HTTP/2 server-side session.
func NewServerSession(reader io.Reader, writer io.Writer) *Session {
	conn := NewConn(reader, writer)
	conn.IsClient = false
	conn.NextStreamID = 2
	return newSession(conn, false)
}

func newSession(conn *Conn, isClient bool) *Session {
	initWindow := int32(conn.PeerSettings.InitialWindowSize)
	localInitWindow := int32(conn.Settings.InitialWindowSize)
	s := &Session{
		conn:             conn,
		streams:          NewStreamManager(isClient, conn.Settings, conn.PeerSettings),
		maxReadFrameSize: int(conn.PeerSettings.MaxFrameSize),
		activeStreams:    make(map[uint32]*streamState),
		dispatchCh:       make(chan dispatchedRequest, 16),
	}
	s.connSendWindow.Store(initWindow)
	s.connRecvWindow.Store(localInitWindow)
	s.connWindowCond = sync.NewCond(&sync.Mutex{})
	return s
}

// startReadLoop ensures the readLoop goroutine is started exactly once.
func (s *Session) startReadLoop() {
	s.readLoopOnce.Do(func() {
		s.readLoopDone = make(chan struct{})
		go s.readLoop()
	})
}

// WaitReadLoop blocks until readLoop exits and returns the error.
func (s *Session) WaitReadLoop() error {
	<-s.readLoopDone
	return s.readLoopErr
}

func (s *Session) readLoop() {
	defer close(s.readLoopDone)
	for {
		frame, err := s.readFrame()
		if err != nil {
			s.readLoopErr = err
			s.broadcastError(err)
			return
		}
		s.handleFrame(frame)
		if s.readLoopErr != nil {
			return
		}
	}
}

func (s *Session) handleFrame(frame Frame) {
	switch frame.Header.Type {
	case FrameHeaders, FrameContinuation:
		s.handleHeaderFrame(frame)
	case FrameData:
		s.handleDataFrame(frame)
	case FrameWindowUpdate:
		s.handleWindowUpdateFrame(frame)
	case FrameRSTStream:
		s.handleRSTStreamFrame(frame)
	case FrameSettings:
		s.handleSettingsFrame(frame)
	case FramePing:
		s.handlePingFrame(frame)
	case FrameGoAway:
		s.readLoopErr = errors.New("http2: received GOAWAY")
		s.broadcastError(s.readLoopErr)
	}
}

func (s *Session) handleHeaderFrame(frame Frame) {
	decoded, err := s.streams.ReceiveHeaderBlockFrame(frame)
	if err != nil {
		s.readLoopErr = err
		s.broadcastError(err)
		return
	}
	if decoded == nil {
		return // CONTINUATION aggregation in progress
	}

	// If stream already registered, this is trailers.
	if existing := s.getStreamState(decoded.StreamID); existing != nil {
		// RFC 7540 §5.1: HEADERS on half-closed (remote) or closed stream is a protocol error.
		state := existing.state.Load()
		if state == stateHalfClosedRemote || state == stateClosed {
			s.writeMu.Lock()
			s.writeRSTStream(decoded.StreamID, ErrProtocolError)
			s.writeMu.Unlock()
			return
		}
		if decoded.EndStream {
			// Decode trailers — propagate malformed trailers as stream error.
			trailers, decErr := s.streams.DecodeTrailerHeaderBlock(decoded.Fields)
			if decErr != nil {
				existing.closed.Store(true)
				// Store terminal error first — streamReader.Read checks this
				// on dataCh close to guarantee the error is returned over EOF.
				existing.termErr.Store(&decErr)
				select {
				case existing.errCh <- decErr:
				default:
				}
				close(existing.dataCh)
				s.writeMu.Lock()
				s.writeRSTStream(existing.id, ErrProtocolError)
				s.writeMu.Unlock()
				s.unregisterStream(existing.id)
				return
			}
			existing.trailers.Store(&trailers)
			close(existing.dataCh)
			if existing.state.CompareAndSwap(stateOpen, stateHalfClosedRemote) {
				// open → half-closed (remote)
			} else if existing.state.CompareAndSwap(stateHalfClosedLocal, stateClosed) {
				s.unregisterStream(existing.id)
			}
		}
		return
	}

	req, decodeErr := s.streams.DecodeRequestHeaderBlock(decoded.Fields)
	if decodeErr != nil {
		return
	}

	// Unconditionally register streamState.
	// END_STREAM only determines initial state, not whether to register.
	initialState := stateOpen
	if decoded.EndStream {
		initialState = stateHalfClosedRemote
	}
	ss := s.registerStream(decoded.StreamID, initialState)

	if decoded.EndStream {
		// No body (GET/HEAD). Close dataCh immediately.
		close(ss.dataCh)
		s.dispatchCh <- dispatchedRequest{
			streamID: decoded.StreamID,
			request:  req,
			bodyCh:   nil,
			errCh:    ss.errCh,
			ss:       ss,
		}
	} else {
		// Body expected; DATA frames arrive via dataCh.
		s.dispatchCh <- dispatchedRequest{
			streamID: decoded.StreamID,
			request:  req,
			bodyCh:   ss.dataCh,
			errCh:    ss.errCh,
			ss:       ss,
		}
	}
}

func (s *Session) handleDataFrame(frame Frame) {
	ss := s.getStreamState(frame.Header.StreamID)
	if ss == nil {
		return
	}

	// Reject DATA on streams that are already half-closed (remote) or closed.
	// RFC 7540 §5.1: receiving DATA on a half-closed (remote) stream is a stream error.
	state := ss.state.Load()
	if state == stateHalfClosedRemote || state == stateClosed {
		s.writeMu.Lock()
		s.writeRSTStream(frame.Header.StreamID, ErrProtocolError)
		s.writeMu.Unlock()
		return
	}

	// Non-blocking push to dataCh. No window replenishment here —
	// WINDOW_UPDATE is driven by streamReader.Read() consumption.
	payload := append([]byte(nil), frame.Payload...)
	select {
	case ss.dataCh <- payload:
	default:
		// dataCh overflow — flow control error.
		ss.closed.Store(true)
		s.writeMu.Lock()
		s.writeRSTStream(ss.id, ErrFlowControlError)
		s.writeMu.Unlock()
		s.unregisterStream(ss.id)
		return
	}

	if frame.Header.Flags&FlagEndStream != 0 {
		close(ss.dataCh)
		if ss.state.CompareAndSwap(stateOpen, stateHalfClosedRemote) {
			// open → half-closed (remote): server response not started yet, keep.
		} else if ss.state.CompareAndSwap(stateHalfClosedLocal, stateClosed) {
			s.unregisterStream(ss.id)
		}
	}
}

func (s *Session) handleWindowUpdateFrame(frame Frame) {
	if len(frame.Payload) != 4 {
		return
	}
	increment := int32(uint32(frame.Payload[0]&0x7F)<<24 |
		uint32(frame.Payload[1])<<16 |
		uint32(frame.Payload[2])<<8 |
		uint32(frame.Payload[3]))
	if increment <= 0 {
		return
	}
	if frame.Header.StreamID == 0 {
		s.connSendWindow.Add(increment)
		s.connWindowCond.Broadcast()
	} else {
		ss := s.getStreamState(frame.Header.StreamID)
		if ss != nil {
			ss.sendWindow.Add(increment)
			ss.windowCond.Broadcast()
		}
	}
}

func (s *Session) handleRSTStreamFrame(frame Frame) {
	ss := s.getStreamState(frame.Header.StreamID)
	if ss != nil {
		ss.closed.Store(true)
		select {
		case ss.errCh <- errStreamReset:
		default:
		}
		s.unregisterStream(ss.id)
	}
}

func (s *Session) handleSettingsFrame(frame Frame) {
	if err := s.applyRemoteSettings(frame); err != nil {
		s.readLoopErr = err
		s.broadcastError(err)
	}
}

func (s *Session) handlePingFrame(frame Frame) {
	if frame.Header.Flags&FlagAck == 0 && len(frame.Payload) == 8 {
		s.writeMu.Lock()
		s.conn.WriteFrame(FrameHeader{
			Type:     FramePing,
			Flags:    FlagAck,
			StreamID: 0,
			Length:   8,
		}, frame.Payload)
		s.writeMu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Phase A: Backward-compatible API (signatures unchanged)
// ---------------------------------------------------------------------------

// ReadRequest reads a complete HTTP/2 request (blocking).
// Internally starts the readLoop and assembles the full body.
func (s *Session) ReadRequest() (uint32, *core.Request, error) {
	s.startReadLoop()
	select {
	case d := <-s.dispatchCh:
		if d.bodyCh == nil {
			return d.streamID, d.request, nil
		}
		// Drain body via streamReader (consumption-driven WINDOW_UPDATE).
		sr := &streamReader{
			dataCh:            d.bodyCh,
			errCh:             d.errCh,
			session:           s,
			streamID:          d.streamID,
			recvWindow:        int32(s.streams.LocalSettings.InitialWindowSize),
			initialWindowSize: int32(s.streams.LocalSettings.InitialWindowSize),
			ss:                d.ss,
		}
		var body bytes.Buffer
		if _, err := io.Copy(&body, sr); err != nil {
			return 0, nil, err
		}
		d.request.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
		d.request.ContentLength = int64(body.Len())
		// Attach trailers if present.
		if t := sr.Trailers(); t != nil {
			d.request.Trailers = *t
		}
		return d.streamID, d.request, nil
	case <-s.readLoopDone:
		return 0, nil, s.readLoopErr
	}
}

// WriteResponse writes a complete HTTP/2 response.
// Uses streamWriter internally for flow-control-compliant DATA writes.
func (s *Session) WriteResponse(streamID uint32, resp *core.Response) error {
	body, _ := resp.ReadAll()
	hasTrailers := resp.Trailers.Count() > 0
	endStream := (len(body) == 0 || !resp.Status.MayHaveBody()) && !hasTrailers

	s.writeMu.Lock()
	headers, err := s.streams.BuildResponseHeaderFrames(streamID, resp, endStream)
	if err != nil {
		s.writeMu.Unlock()
		return err
	}
	for _, frame := range headers {
		if err := s.conn.WriteFrame(frame.Header, frame.Payload); err != nil {
			s.writeMu.Unlock()
			return err
		}
	}
	s.writeMu.Unlock()

	if endStream {
		s.transitionStreamClosed(streamID)
		return nil
	}

	// Write body via streamWriter (flow-control compliant).
	if len(body) > 0 && resp.Status.MayHaveBody() {
		ss := s.getStreamState(streamID)
		if ss == nil {
			return errStreamClosed
		}
		w := &streamWriter{session: s, streamID: streamID, ss: ss}
		if _, err := w.Write(body); err != nil {
			return err
		}
	}

	if hasTrailers {
		// Write trailers with END_STREAM (no END_STREAM on DATA).
		s.writeMu.Lock()
		trailerFrames, err := s.streams.BuildTrailerFrames(streamID, &resp.Trailers, true)
		if err != nil {
			s.writeMu.Unlock()
			return err
		}
		for _, frame := range trailerFrames {
			if err := s.conn.WriteFrame(frame.Header, frame.Payload); err != nil {
				s.writeMu.Unlock()
				return err
			}
		}
		s.writeMu.Unlock()
		s.transitionStreamClosed(streamID)
	} else {
		// Send END_STREAM via empty DATA frame.
		ss := s.getStreamState(streamID)
		if ss == nil {
			return errStreamClosed
		}
		w := &streamWriter{session: s, streamID: streamID, ss: ss}
		if err := w.Close(); err != nil {
			return err
		}
	}

	return nil
}

// transitionStreamClosed advances stream state after server sends END_STREAM.
func (s *Session) transitionStreamClosed(streamID uint32) {
	ss := s.getStreamState(streamID)
	if ss == nil {
		return
	}
	if ss.state.CompareAndSwap(stateOpen, stateHalfClosedLocal) {
		// open → half-closed (local)
	} else if ss.state.CompareAndSwap(stateHalfClosedRemote, stateClosed) {
		s.unregisterStream(streamID)
	}
}

// ---------------------------------------------------------------------------
// Phase B: Streaming API
// ---------------------------------------------------------------------------

// ReadStreamRequest reads an HTTP/2 request and returns a streamReader for body.
// Returns (streamID, request, streamReader, error).
// The caller reads the body via streamReader.Read() and the streamReader handles
// consumption-driven WINDOW_UPDATE automatically.
func (s *Session) ReadStreamRequest() (uint32, *core.Request, *streamReader, error) {
	s.startReadLoop()
	select {
	case d := <-s.dispatchCh:
		sr := &streamReader{
			dataCh:            d.bodyCh,
			errCh:             d.errCh,
			session:           s,
			streamID:          d.streamID,
			recvWindow:        int32(s.streams.LocalSettings.InitialWindowSize),
			initialWindowSize: int32(s.streams.LocalSettings.InitialWindowSize),
			ss:                d.ss,
		}
		return d.streamID, d.request, sr, nil
	case <-s.readLoopDone:
		return 0, nil, nil, s.readLoopErr
	}
}

// WriteResponseHead writes response headers and returns a streamWriter for body.
// Returns (nil, nil) for no-body responses (status 204, 304, etc.).
func (s *Session) WriteResponseHead(streamID uint32, resp *core.Response) (*streamWriter, error) {
	hasTrailers := resp.Trailers.Count() > 0
	endStream := !resp.Status.MayHaveBody() && !hasTrailers

	s.writeMu.Lock()
	headers, err := s.streams.BuildResponseHeaderFrames(streamID, resp, endStream)
	if err != nil {
		s.writeMu.Unlock()
		return nil, err
	}
	for _, frame := range headers {
		if err := s.conn.WriteFrame(frame.Header, frame.Payload); err != nil {
			s.writeMu.Unlock()
			return nil, err
		}
	}
	s.writeMu.Unlock()

	ss := s.getStreamState(streamID)
	if ss == nil {
		return nil, errStreamClosed
	}
	if endStream {
		s.transitionStreamClosed(streamID)
		return nil, nil
	}
	return &streamWriter{session: s, streamID: streamID, ss: ss}, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (s *Session) registerStream(id uint32, initialState int32) *streamState {
	ss := &streamState{
		id:     id,
		dataCh: make(chan []byte, dataChCapacity),
		errCh:  make(chan error, 1),
	}
	ss.state.Store(initialState)
	ss.sendWindow.Store(int32(s.streams.PeerSettings.InitialWindowSize))
	ss.windowCond = sync.NewCond(&sync.Mutex{})
	s.streamMu.Lock()
	s.activeStreams[id] = ss
	s.streamMu.Unlock()
	return ss
}

func (s *Session) unregisterStream(id uint32) {
	s.streamMu.Lock()
	delete(s.activeStreams, id)
	s.streamMu.Unlock()
}

func (s *Session) getStreamState(id uint32) *streamState {
	s.streamMu.Lock()
	ss := s.activeStreams[id]
	s.streamMu.Unlock()
	return ss
}

func (s *Session) broadcastError(err error) {
	s.streamMu.Lock()
	for _, ss := range s.activeStreams {
		ss.closed.Store(true)
		// Skip streams that have already received END_STREAM (request data complete).
		// Connection errors don't affect streams whose data is fully received.
		state := ss.state.Load()
		if state == stateHalfClosedRemote || state == stateClosed {
			continue
		}
		select {
		case ss.errCh <- err:
		default:
		}
	}
	s.streamMu.Unlock()
}

func (s *Session) writeRSTStream(streamID uint32, code ErrorCode) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(code))
	s.conn.WriteFrame(FrameHeader{
		Type:     FrameRSTStream,
		Length:   4,
		StreamID: streamID,
	}, payload)
}

func (s *Session) writeWindowUpdate(streamID uint32, increment uint32) {
	payload := make([]byte, 4)
	payload[0] = byte((increment >> 24) & 0x7F)
	payload[1] = byte((increment >> 16) & 0xFF)
	payload[2] = byte((increment >> 8) & 0xFF)
	payload[3] = byte(increment & 0xFF)
	s.conn.WriteFrame(FrameHeader{
		Type:     FrameWindowUpdate,
		Length:   4,
		StreamID: streamID,
	}, payload)
}

func (s *Session) readFrame() (Frame, error) {
	maxSize := s.maxReadFrameSize
	if maxSize <= 0 {
		maxSize = int(s.streams.LocalSettings.MaxFrameSize)
	}
	if maxSize <= 0 {
		maxSize = 16384
	}
	return s.conn.ReadFrame(maxSize)
}

func (s *Session) applyRemoteSettings(frame Frame) error {
	if frame.Header.StreamID != 0 {
		return errors.New("http2 settings frame must use stream 0")
	}
	if frame.Header.Flags&FlagAck != 0 {
		return nil
	}

	// Capture old InitialWindowSize before applying new settings.
	oldInitWindow := int32(s.conn.PeerSettings.InitialWindowSize)

	if err := ApplySettingsPayload(&s.conn.PeerSettings, frame.Payload); err != nil {
		return err
	}
	s.streams.PeerSettings = s.conn.PeerSettings
	if size := int(s.conn.PeerSettings.MaxFrameSize); size > 0 {
		s.maxReadFrameSize = size
	}

	// RFC 7540 §6.9.2: SETTINGS_INITIAL_WINDOW_SIZE delta applies to all
	// active streams. A decrease can cause the send window to go negative.
	newInitWindow := int32(s.conn.PeerSettings.InitialWindowSize)
	if delta := newInitWindow - oldInitWindow; delta != 0 {
		s.streamMu.Lock()
		for _, ss := range s.activeStreams {
			ss.sendWindow.Add(delta)
			ss.windowCond.Broadcast()
		}
		s.streamMu.Unlock()
	}

	// Encoder update + ACK write under writeMu (serializes with HPACK encoding).
	s.writeMu.Lock()
	s.streams.encoder.SetMaxDynamicTableSizeLimit(s.conn.PeerSettings.HeaderTableSize)
	err := s.conn.WriteFrame(FrameHeader{Type: FrameSettings, Flags: FlagAck, StreamID: 0}, nil)
	s.writeMu.Unlock()
	return err
}
