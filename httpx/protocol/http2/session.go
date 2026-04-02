package http2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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
const (
	dataChCapacity     = 8    // ceil(65535/16384)+1 per-stream data buffer
	dispatchChCapacity = 4096 // readLoop dispatch queue — large enough for browser bursts
)

var (
	// ErrStreamClosedWrite is returned when writing to a closed stream.
	ErrStreamClosedWrite = errors.New("http2: stream closed")
	// ErrStreamReset is returned when the peer sends RST_STREAM.
	ErrStreamReset = errors.New("http2: stream reset by peer")
	// ErrDataOverflow is returned on dataCh overflow (flow control violation).
	ErrDataOverflow = errors.New("http2: flow control error")
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
			r.session.maybeSendConnWindowUpdate(n)
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
		return 0, ErrStreamClosedWrite
	}
	written := 0
	for written < len(p) {
		if w.ss.closed.Load() {
			return written, ErrStreamClosedWrite
		}

		// Wait for stream-level send window.
		for w.ss.sendWindow.Load() <= 0 {
			w.ss.windowCond.L.Lock()
			w.ss.windowCond.Wait()
			w.ss.windowCond.L.Unlock()
			if w.ss.closed.Load() {
				return written, ErrStreamClosedWrite
			}
		}

		// Wait for connection-level send window (cannot busy-wait).
		for w.session.connSendWindow.Load() <= 0 {
			w.session.connWindowCond.L.Lock()
			w.session.connWindowCond.Wait()
			w.session.connWindowCond.L.Unlock()
			if w.ss.closed.Load() {
				return written, ErrStreamClosedWrite
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

	// Flush buffered DATA frames so the peer receives data without waiting
	// for the buffer to fill. This is critical for CDN progressive loading.
	_ = w.session.Flush()

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

// WriteFinal writes p as DATA frames with END_STREAM on the last frame, then flushes.
// This ensures body data and END_STREAM are delivered in the same flush — the peer
// never observes body data without END_STREAM, preventing "incomplete response" errors.
// If p is empty, behaves like Close (sends empty END_STREAM frame).
func (w *streamWriter) WriteFinal(p []byte) error {
	if len(p) == 0 {
		return w.Close()
	}
	if w.ss.closed.Load() {
		return ErrStreamClosedWrite
	}

	written := 0
	for written < len(p) {
		if w.ss.closed.Load() {
			return ErrStreamClosedWrite
		}
		for w.ss.sendWindow.Load() <= 0 {
			w.ss.windowCond.L.Lock()
			w.ss.windowCond.Wait()
			w.ss.windowCond.L.Unlock()
			if w.ss.closed.Load() {
				return ErrStreamClosedWrite
			}
		}
		for w.session.connSendWindow.Load() <= 0 {
			w.session.connWindowCond.L.Lock()
			w.session.connWindowCond.Wait()
			w.session.connWindowCond.L.Unlock()
			if w.ss.closed.Load() {
				return ErrStreamClosedWrite
			}
		}

		maxFrame := int(w.session.streams.PeerSettings.MaxFrameSize)
		if maxFrame <= 0 {
			maxFrame = 16384
		}

		chunk := w.reserveWindow(len(p)-written, maxFrame)
		if chunk <= 0 {
			continue
		}

		isLast := written+chunk == len(p)
		flags := uint8(0)
		if isLast {
			flags = FlagEndStream
		}

		w.session.writeMu.Lock()
		err := w.session.conn.WriteFrame(FrameHeader{
			Length:   uint32(chunk),
			Type:     FrameData,
			Flags:    flags,
			StreamID: w.streamID,
		}, p[written:written+chunk])
		w.session.writeMu.Unlock()
		if err != nil {
			w.ss.sendWindow.Add(int32(chunk))
			w.session.connSendWindow.Add(int32(chunk))
			return err
		}
		written += chunk
	}

	if w.ss.state.CompareAndSwap(stateOpen, stateHalfClosedLocal) {
		// open → half-closed (local)
	} else if w.ss.state.CompareAndSwap(stateHalfClosedRemote, stateClosed) {
		w.session.unregisterStream(w.streamID)
	}
	return w.session.Flush()
}

// Close sends an empty DATA frame with END_STREAM and flushes.
// For streaming responses, prefer WriteFinal which combines the last body
// chunk with END_STREAM in a single frame.
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
	return w.session.Flush()
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
	connRecvMu     sync.Mutex
	goAwayReceived atomic.Bool

	// Request dispatch channel
	dispatchCh chan dispatchedRequest
}

// NewServerSession creates an HTTP/2 server-side session.
// Sends the server connection preface (SETTINGS frame) and reads the
// client connection preface (24-byte magic + SETTINGS frame).
func NewServerSession(reader io.Reader, writer io.Writer) (*Session, error) {
	conn := NewConn(reader, writer)
	conn.IsClient = false
	conn.NextStreamID = 2

	// RFC 7540 §3.3: Server connection preface — send SETTINGS frame.
	payload := EncodeSettingsPayload(conn.Settings, nil)
	if err := conn.WriteFrame(FrameHeader{Length: uint32(len(payload)), Type: FrameSettings, StreamID: 0}, payload); err != nil {
		return nil, fmt.Errorf("http2 server preface write: %w", err)
	}
	// Flush SETTINGS to wire immediately.
	if err := flushWriter(writer); err != nil {
		return nil, fmt.Errorf("http2 server preface flush: %w", err)
	}

	// RFC 7540 §3.5: Read and validate client connection preface magic.
	magic := make([]byte, len(Preface))
	if _, err := io.ReadFull(reader, magic); err != nil {
		return nil, fmt.Errorf("http2 client preface read: %w", err)
	}
	if string(magic) != Preface {
		return nil, fmt.Errorf("http2 invalid client preface")
	}

	s := newSession(conn, false)

	// Read the client's SETTINGS frame (first frame after preface).
	frame, err := conn.ReadFrame(1<<20 + 1)
	if err != nil {
		return nil, fmt.Errorf("http2 client settings read: %w", err)
	}
	if frame.Header.Type != FrameSettings {
		return nil, fmt.Errorf("http2 expected SETTINGS frame, got %d", frame.Header.Type)
	}
	if err := s.applyRemoteSettings(frame); err != nil {
		return nil, fmt.Errorf("http2 client settings apply: %w", err)
	}

	return s, nil
}

// flushWriter flushes the writer if it implements Flusher.
func flushWriter(w io.Writer) error {
	if f, ok := w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

func newSession(conn *Conn, isClient bool) *Session {
	initWindow := int32(conn.PeerSettings.InitialWindowSize)
	localInitWindow := int32(conn.Settings.InitialWindowSize)
	s := &Session{
		conn:             conn,
		streams:          NewStreamManager(isClient, conn.Settings, conn.PeerSettings),
		maxReadFrameSize: int(conn.Settings.MaxFrameSize),
		activeStreams:    make(map[uint32]*streamState),
		dispatchCh:       make(chan dispatchedRequest, dispatchChCapacity),
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
			// RFC 7540 §6.8: GOAWAY means "no new streams", not "kill everything".
			// After GOAWAY, EOF is the expected end of the session — do NOT
			// broadcastError to active streams.  This allows handler goroutines
			// to attempt writing responses.  If the TCP write-side is still open
			// (peer half-closed with FIN), the response will be delivered.
			// If the connection is fully reset, the write will fail naturally
			// with a broken-pipe / connection-reset error.
			if !s.goAwayReceived.Load() {
				s.broadcastError(err)
			}
			return
		}
		s.handleFrame(frame)
		frame.Release()
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
		// RFC 7540 §6.8: GOAWAY means "no new streams", not "kill everything".
		// Continue the readLoop to process WINDOW_UPDATE, PING, etc. for
		// existing streams so the server can finish sending responses.
		s.goAwayReceived.Store(true)
	case FramePriority:
		// RFC 7540 §5.3: PRIORITY frames are 5 bytes. Servers may ignore
		// the priority signal but MUST validate the frame length.
		if len(frame.Payload) != 5 {
			s.failConnection(errors.New("http2 invalid priority frame length"))
		}
	}
}

func (s *Session) handleHeaderFrame(frame Frame) {
	decoded, err := s.streams.ReceiveHeaderBlockFrame(frame)
	if err != nil {
		s.failConnection(err)
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
		s.writeMu.Lock()
		s.writeRSTStream(decoded.StreamID, ErrProtocolError)
		s.writeMu.Unlock()
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
		s.failConnection(errors.New("http2 data for unknown stream"))
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
	payload := frame.Payload
	if frame.Header.Flags&FlagPadded != 0 {
		if len(payload) == 0 {
			s.failConnection(errors.New("http2 padded data frame with empty payload"))
			return
		}
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			s.failConnection(errors.New("http2 data frame padding exceeds payload"))
			return
		}
		payload = payload[:len(payload)-padLen]
	}
	if s.connRecvWindow.Add(-int32(len(frame.Payload))) < 0 {
		ss.closed.Store(true)
		s.failConnection(ErrDataOverflow)
		return
	}

	// Non-blocking push to dataCh. No window replenishment here —
	// WINDOW_UPDATE is driven by streamReader.Read() consumption.
	payload = append([]byte(nil), payload...)
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
		s.failConnection(errors.New("http2 invalid window update length"))
		return
	}
	increment := int32(uint32(frame.Payload[0]&0x7F)<<24 |
		uint32(frame.Payload[1])<<16 |
		uint32(frame.Payload[2])<<8 |
		uint32(frame.Payload[3]))
	if increment <= 0 {
		s.failConnection(errors.New("http2 invalid window increment"))
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
		case ss.errCh <- ErrStreamReset:
		default:
		}
		s.unregisterStream(ss.id)
	}
}

func (s *Session) handleSettingsFrame(frame Frame) {
	if err := s.applyRemoteSettings(frame); err != nil {
		s.failConnection(err)
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
		return s.Flush()
	}

	// Write body via streamWriter (flow-control compliant).
	if len(body) > 0 && resp.Status.MayHaveBody() {
		ss := s.getStreamState(streamID)
		if ss == nil {
			return ErrStreamClosedWrite
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
		return s.Flush()
	} else {
		// Send END_STREAM via empty DATA frame.
		ss := s.getStreamState(streamID)
		if ss == nil {
			return ErrStreamClosedWrite
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

	// Flush headers immediately so the client can start processing.
	if err := s.Flush(); err != nil {
		return nil, err
	}

	ss := s.getStreamState(streamID)
	if ss == nil {
		return nil, ErrStreamClosedWrite
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
		// Skip streams that have already received END_STREAM (request data complete).
		// Connection errors don't affect streams whose data is fully received.
		state := ss.state.Load()
		if state == stateHalfClosedRemote || state == stateClosed {
			continue
		}
		ss.closed.Store(true)
		select {
		case ss.errCh <- err:
		default:
		}
	}
	s.streamMu.Unlock()
}

func (s *Session) failConnection(err error) {
	if err == nil || s.readLoopErr != nil {
		return
	}
	s.readLoopErr = err
	s.broadcastError(err)
}

func (s *Session) maybeSendConnWindowUpdate(consumed int) {
	if consumed <= 0 {
		return
	}
	initialWindowSize := int32(s.streams.LocalSettings.InitialWindowSize)
	if initialWindowSize <= 0 {
		return
	}

	s.connRecvMu.Lock()
	if s.connRecvWindow.Load() <= initialWindowSize/2 {
		increment := initialWindowSize - s.connRecvWindow.Load()
		s.connRecvWindow.Store(initialWindowSize)
		s.connRecvMu.Unlock()
		s.writeMu.Lock()
		s.writeWindowUpdate(0, uint32(increment))
		s.writeMu.Unlock()
		return
	}
	s.connRecvMu.Unlock()
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
	if err != nil {
		return err
	}
	return s.Flush()
}

// Flush flushes any buffered write data to the underlying connection.
func (s *Session) Flush() error {
	return flushWriter(s.conn.writer)
}

// LastStreamID returns the highest peer-initiated stream ID seen by this session.
func (s *Session) LastStreamID() uint32 {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	var maxID uint32
	for id := range s.activeStreams {
		if id > maxID {
			maxID = id
		}
	}
	return maxID
}

// SendGoAway sends a GOAWAY frame to the peer (RFC 7540 §6.8).
// After this call the peer should not open new streams on this connection.
func (s *Session) SendGoAway(lastStreamID uint32, code ErrorCode) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	payload := make([]byte, 8)
	payload[0] = byte((lastStreamID >> 24) & 0x7F)
	payload[1] = byte((lastStreamID >> 16) & 0xFF)
	payload[2] = byte((lastStreamID >> 8) & 0xFF)
	payload[3] = byte(lastStreamID & 0xFF)
	binary.BigEndian.PutUint32(payload[4:8], uint32(code))
	if err := s.conn.WriteFrame(FrameHeader{
		Length:   8,
		Type:     FrameGoAway,
		StreamID: 0,
	}, payload); err != nil {
		return err
	}
	return s.Flush()
}

// Close gracefully shuts down the session: sends GOAWAY and waits for
// the readLoop to exit.
func (s *Session) Close() error {
	_ = s.SendGoAway(s.LastStreamID(), ErrNoError)
	if s.readLoopDone != nil {
		<-s.readLoopDone
	}
	return nil
}
