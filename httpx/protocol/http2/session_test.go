package http2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/dnsoa/net/httpx/core"
)

// --- State transition tests (no I/O needed) ---

func TestStreamStateCASOpenToClosedRemote(t *testing.T) {
	ss := &streamState{id: 1}
	ss.state.Store(stateOpen)
	ss.sendWindow.Store(65535)

	if !ss.state.CompareAndSwap(stateOpen, stateHalfClosedRemote) {
		t.Fatal("CAS open → half-closed remote failed")
	}
	if !ss.state.CompareAndSwap(stateHalfClosedRemote, stateClosed) {
		t.Fatal("CAS half-closed remote → closed failed")
	}
}

func TestStreamStateCASOpenToClosedLocal(t *testing.T) {
	ss := &streamState{id: 1}
	ss.state.Store(stateOpen)

	if !ss.state.CompareAndSwap(stateOpen, stateHalfClosedLocal) {
		t.Fatal("CAS open → half-closed local failed")
	}
	if !ss.state.CompareAndSwap(stateHalfClosedLocal, stateClosed) {
		t.Fatal("CAS half-closed local → closed failed")
	}
}

// --- broadcastError test ---

func TestBroadcastError(t *testing.T) {
	s := NewServerSession(nil, nil)
	ss1 := s.registerStream(1, stateOpen)
	ss2 := s.registerStream(3, stateOpen)

	testErr := errors.New("test error")
	s.broadcastError(testErr)

	if !ss1.closed.Load() {
		t.Fatal("expected ss1 to be closed")
	}
	if !ss2.closed.Load() {
		t.Fatal("expected ss2 to be closed")
	}
	select {
	case err := <-ss1.errCh:
		if err != testErr {
			t.Fatalf("unexpected error %v", err)
		}
	default:
		t.Fatal("expected error in ss1.errCh")
	}
}

// --- streamReader with nil dataCh returns EOF ---

func TestStreamReaderNilDataCh(t *testing.T) {
	sr := &streamReader{
		dataCh:            nil,
		session:           NewServerSession(nil, nil),
		recvWindow:        65535,
		initialWindowSize: 65535,
	}
	buf := make([]byte, 10)
	n, err := sr.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes, got %d", n)
	}
}

// --- streamReader reads from dataCh ---

func TestStreamReaderFromDataCh(t *testing.T) {
	dataCh := make(chan []byte, 4)
	errCh := make(chan error, 1)

	sr := &streamReader{
		dataCh:            dataCh,
		errCh:             errCh,
		session:           NewServerSession(nil, nil),
		recvWindow:        65535,
		initialWindowSize: 65535,
	}

	// Feed data.
	dataCh <- []byte("hello ")
	dataCh <- []byte("world")
	close(dataCh)

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, sr); err != nil {
		t.Fatalf("read: %v", err)
	}
	if buf.String() != "hello world" {
		t.Fatalf("unexpected body %q", buf.String())
	}
}

// --- streamReader error propagation ---

func TestStreamReaderError(t *testing.T) {
	dataCh := make(chan []byte, 1)
	errCh := make(chan error, 1)

	sr := &streamReader{
		dataCh:            dataCh,
		errCh:             errCh,
		session:           NewServerSession(nil, nil),
		recvWindow:        65535,
		initialWindowSize: 65535,
	}

	testErr := errors.New("stream reset")
	errCh <- testErr

	buf := make([]byte, 10)
	_, err := sr.Read(buf)
	if err != testErr {
		t.Fatalf("expected testErr, got %v", err)
	}
}

// --- streamState concurrent access ---

func TestStreamStateConcurrentAccess(t *testing.T) {
	s := NewServerSession(nil, nil)
	const numStreams = 100
	var wg sync.WaitGroup

	// Concurrent registration.
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			ss := s.registerStream(id, stateOpen)
			if ss.id != id {
				t.Errorf("unexpected id %d", ss.id)
			}
		}(uint32(i*2 + 1))
	}
	wg.Wait()

	// Verify all registered.
	s.streamMu.Lock()
	if len(s.activeStreams) != numStreams {
		t.Fatalf("expected %d streams, got %d", numStreams, len(s.activeStreams))
	}
	s.streamMu.Unlock()

	// Concurrent unregistration.
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			s.unregisterStream(id)
		}(uint32(i*2 + 1))
	}
	wg.Wait()

	s.streamMu.Lock()
	if len(s.activeStreams) != 0 {
		t.Fatalf("expected 0 streams, got %d", len(s.activeStreams))
	}
	s.streamMu.Unlock()
}

// --- streamWriter basic write and close ---

func TestStreamWriterWriteAndClose(t *testing.T) {
	var written bytes.Buffer
	conn := NewConn(nil, &written)
	conn.IsClient = false
	s := NewServerSession(nil, nil)
	// Override conn for direct frame writing.
	s.conn = conn
	s.streams.PeerSettings.MaxFrameSize = 16384

	ss := s.registerStream(1, stateHalfClosedRemote)
	ss.sendWindow.Store(65535)
	s.connSendWindow.Store(65535)

	w := &streamWriter{session: s, streamID: 1, ss: ss}
	n, err := w.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != 5 {
		t.Fatalf("unexpected written %d", n)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Stream should be unregistered (half-closed remote → closed).
	if s.getStreamState(1) != nil {
		t.Fatal("expected stream to be unregistered after close")
	}
}

// --- streamWriter respects closed flag ---

func TestStreamWriterClosed(t *testing.T) {
	s := NewServerSession(nil, nil)
	ss := s.registerStream(1, stateOpen)
	ss.closed.Store(true)

	w := &streamWriter{session: s, streamID: 1, ss: ss}
	_, err := w.Write([]byte("x"))
	if err == nil {
		t.Fatal("expected error on closed stream")
	}
}

// --- Full integration: ReadRequest from frame bytes ---

func TestReadRequestFromFrameBytes(t *testing.T) {
	// Build the client request frames into a buffer, then feed to server session.
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	stream, err := mgr.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodGet, "https://example.com/path?q=1")
	req.Version = core.VersionHTTP2

	frames, err := mgr.BuildRequestHeaderFrames(stream.ID, req, true)
	if err != nil {
		t.Fatalf("build frames: %v", err)
	}

	// Serialize frames into a buffer.
	var frameBuf bytes.Buffer
	for _, frame := range frames {
		serialized := frame.Header.Serialize()
		frameBuf.Write(serialized[:])
		if len(frame.Payload) > 0 {
			frameBuf.Write(frame.Payload)
		}
	}

	// Create server session reading from the buffer.
	var discard bytes.Buffer
	server := NewServerSession(&frameBuf, &discard)

	streamID, gotReq, err := server.ReadRequest()
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	defer core.ReleaseRequest(gotReq)
	if streamID != stream.ID {
		t.Fatalf("unexpected stream ID %d", streamID)
	}
	if gotReq.Method != core.MethodGet {
		t.Fatalf("unexpected method %v", gotReq.Method)
	}
	if string(gotReq.URI.Path) != "/path" {
		t.Fatalf("unexpected path %q", gotReq.URI.Path)
	}
	if string(gotReq.URI.Query) != "q=1" {
		t.Fatalf("unexpected query %q", gotReq.URI.Query)
	}
}

// --- Full integration: ReadRequest with body ---

func TestReadRequestWithBodyFromFrameBytes(t *testing.T) {
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	stream, err := mgr.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodPost, "https://example.com/upload")
	req.Version = core.VersionHTTP2

	frames, err := mgr.BuildRequestHeaderFrames(stream.ID, req, false)
	if err != nil {
		t.Fatalf("build frames: %v", err)
	}

	var frameBuf bytes.Buffer
	for _, frame := range frames {
		serialized := frame.Header.Serialize()
		frameBuf.Write(serialized[:])
		if len(frame.Payload) > 0 {
			frameBuf.Write(frame.Payload)
		}
	}

	// Add DATA frame with END_STREAM.
	body := []byte("request body")
	dataHeader := FrameHeader{
		Length:   uint32(len(body)),
		Type:     FrameData,
		Flags:    FlagEndStream,
		StreamID: stream.ID,
	}
	serialized := dataHeader.Serialize()
	frameBuf.Write(serialized[:])
	frameBuf.Write(body)

	var discard bytes.Buffer
	server := NewServerSession(&frameBuf, &discard)

	streamID, gotReq, err := server.ReadRequest()
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	defer core.ReleaseRequest(gotReq)
	if streamID != stream.ID {
		t.Fatalf("unexpected stream ID %d", streamID)
	}

	respBody, _ := gotReq.ReadAll()
	if string(respBody) != "request body" {
		t.Fatalf("unexpected body %q", respBody)
	}
}

// --- WriteResponse integration ---

func TestWriteResponseIntegration(t *testing.T) {
	// Set up server session with buffer writer.
	var out bytes.Buffer
	server := NewServerSession(nil, &out)
	server.conn = NewConn(nil, &out)

	// Register stream state.
	server.registerStream(1, stateHalfClosedRemote)

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP2
	resp.Status = core.NewStatus(200)
	resp.Headers.SetString("Content-Type", "text/plain")
	resp.SetBody(io.NopCloser(bytes.NewReader([]byte("OK"))))

	if err := server.WriteResponse(1, resp); err != nil {
		t.Fatalf("write response: %v", err)
	}

	// Verify frames were written to output.
	if out.Len() == 0 {
		t.Fatal("expected output bytes")
	}

	// Stream should be cleaned up.
	if server.getStreamState(1) != nil {
		t.Fatal("expected stream to be unregistered")
	}
}

// --- WriteResponse no-body (204) ---

func TestWriteResponseNoBody(t *testing.T) {
	var out bytes.Buffer
	server := NewServerSession(nil, &out)
	server.conn = NewConn(nil, &out)
	server.registerStream(1, stateHalfClosedRemote)

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP2
	resp.Status = core.NewStatus(204)

	if err := server.WriteResponse(1, resp); err != nil {
		t.Fatalf("write response: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("expected output bytes")
	}
	if server.getStreamState(1) != nil {
		t.Fatal("expected stream to be unregistered")
	}
}

// --- WriteResponseHead returns nil for no-body ---

func TestWriteResponseHeadNoBody(t *testing.T) {
	var out bytes.Buffer
	server := NewServerSession(nil, &out)
	server.conn = NewConn(nil, &out)
	server.registerStream(1, stateHalfClosedRemote)

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP2
	resp.Status = core.NewStatus(304)
	resp.Headers.SetString("ETag", `"abc"`)

	w, err := server.WriteResponseHead(1, resp)
	if err != nil {
		t.Fatalf("write response head: %v", err)
	}
	if w != nil {
		t.Fatal("expected nil streamWriter for 304 response")
	}
	if server.getStreamState(1) != nil {
		t.Fatal("expected stream to be unregistered")
	}
}

// --- RST_STREAM handling ---

func TestRSTStreamFrameHandling(t *testing.T) {
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	stream, err := mgr.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	req := core.AcquireRequest()
	initRequest(req, core.MethodPost, "https://example.com/upload")
	req.Version = core.VersionHTTP2

	frames, err := mgr.BuildRequestHeaderFrames(stream.ID, req, false)
	core.ReleaseRequest(req)
	if err != nil {
		t.Fatalf("build frames: %v", err)
	}

	var frameBuf bytes.Buffer
	for _, frame := range frames {
		serialized := frame.Header.Serialize()
		frameBuf.Write(serialized[:])
		if len(frame.Payload) > 0 {
			frameBuf.Write(frame.Payload)
		}
	}

	// Add RST_STREAM.
	rstPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(rstPayload, uint32(ErrCancel))
	rstHeader := FrameHeader{Type: FrameRSTStream, Length: 4, StreamID: stream.ID}
	serialized := rstHeader.Serialize()
	frameBuf.Write(serialized[:])
	frameBuf.Write(rstPayload)

	var discard bytes.Buffer
	server := NewServerSession(&frameBuf, &discard)

	_, _, err = server.ReadRequest()
	if err == nil {
		t.Fatal("expected error after RST_STREAM")
	}
}

// --- WINDOW_UPDATE parsing ---

func TestWindowUpdateFrameParsing(t *testing.T) {
	s := NewServerSession(nil, nil)
	ss := s.registerStream(1, stateOpen)
	ss.sendWindow.Store(0) // Window exhausted.

	// Simulate receiving WINDOW_UPDATE for stream.
	frame := Frame{
		Header:  FrameHeader{Type: FrameWindowUpdate, Length: 4, StreamID: 1},
		Payload: []byte{0x00, 0x00, 0x01, 0x00}, // increment = 256
	}
	s.handleWindowUpdateFrame(frame)

	if ss.sendWindow.Load() != 256 {
		t.Fatalf("unexpected send window %d, want 256", ss.sendWindow.Load())
	}
}

// --- Concurrent WriteResponse stress test ---

func TestConcurrentWriteResponse(t *testing.T) {
	var out bytes.Buffer
	server := NewServerSession(nil, &out)
	server.conn = NewConn(nil, &out)

	const numStreams = 10
	for i := 0; i < numStreams; i++ {
		server.registerStream(uint32(i+1), stateHalfClosedRemote)
	}

	var wg sync.WaitGroup
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			streamID := uint32(idx + 1)
			resp := core.AcquireResponse()
			defer core.ReleaseResponse(resp)
			resp.Version = core.VersionHTTP2
			resp.Status = core.NewStatus(200)
			resp.Headers.SetString("X-Stream", string(core.AppendInt(nil, idx)))
			resp.SetBody(io.NopCloser(bytes.NewReader([]byte("response body"))))
			if err := server.WriteResponse(streamID, resp); err != nil {
				t.Errorf("write response %d: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()
}

// --- registerStream/unregisterStream ---

func TestRegisterUnregisterStream(t *testing.T) {
	s := NewServerSession(nil, nil)

	ss := s.registerStream(1, stateOpen)
	if ss == nil {
		t.Fatal("expected non-nil streamState")
	}
	if ss.state.Load() != stateOpen {
		t.Fatalf("unexpected initial state %d", ss.state.Load())
	}

	if got := s.getStreamState(1); got != ss {
		t.Fatal("getStreamState mismatch")
	}

	s.unregisterStream(1)
	if s.getStreamState(1) != nil {
		t.Fatal("expected nil after unregister")
	}
}

// --- transitionStreamClosed ---

func TestTransitionStreamClosed(t *testing.T) {
	s := NewServerSession(nil, nil)

	// Case 1: half-closed remote → closed.
	ss := s.registerStream(1, stateHalfClosedRemote)
	s.transitionStreamClosed(1)
	if s.getStreamState(1) != nil {
		t.Fatal("expected stream to be unregistered (half-closed remote → closed)")
	}

	// Case 2: open → half-closed local (stream still registered).
	ss = s.registerStream(3, stateOpen)
	s.transitionStreamClosed(3)
	if s.getStreamState(3) == nil {
		t.Fatal("expected stream to remain registered (open → half-closed local)")
	}
	if ss.state.Load() != stateHalfClosedLocal {
		t.Fatalf("unexpected state %d", ss.state.Load())
	}
}

// --- dataCh capacity ---

func TestDataChCapacity(t *testing.T) {
	s := NewServerSession(nil, nil)
	ss := s.registerStream(1, stateOpen)
	if cap(ss.dataCh) != dataChCapacity {
		t.Fatalf("unexpected dataCh capacity %d, want %d", cap(ss.dataCh), dataChCapacity)
	}
}

// --- sendWindow initialization ---

func TestSendWindowInitialization(t *testing.T) {
	settings := DefaultConnectionSettings()
	settings.InitialWindowSize = 32768
	s := NewServerSession(nil, nil)
	s.streams.PeerSettings.InitialWindowSize = 32768

	ss := s.registerStream(1, stateOpen)
	if ss.sendWindow.Load() != 32768 {
		t.Fatalf("unexpected send window %d, want 32768", ss.sendWindow.Load())
	}
}

// --- connSendWindow initialization ---

func TestConnSendWindowInit(t *testing.T) {
	conn := NewConn(nil, nil)
	conn.PeerSettings.InitialWindowSize = 32768
	s := newSession(conn, false)

	if s.connSendWindow.Load() != 32768 {
		t.Fatalf("unexpected conn send window %d", s.connSendWindow.Load())
	}
}

// --- Concurrent streamWriter must not exceed connection window ---

func TestConcurrentWindowAccounting(t *testing.T) {
	var out bytes.Buffer
	server := NewServerSession(nil, &out)
	server.conn = NewConn(nil, &out)

	// Small connection window to stress the CAS reservation.
	const connWindow int32 = 4096
	server.connSendWindow.Store(connWindow)

	const numStreams = 8
	writers := make([]*streamWriter, numStreams)
	for i := 0; i < numStreams; i++ {
		ss := server.registerStream(uint32(i+1), stateHalfClosedRemote)
		ss.sendWindow.Store(1 << 20) // per-stream window much larger
		writers[i] = &streamWriter{session: server, streamID: uint32(i + 1), ss: ss}
	}

	// Each writer tries to write 2048 bytes.
	// Total demand = 8 * 2048 = 16384 > connWindow (4096).
	// Only connWindow bytes should be written; the rest blocks.
	body := make([]byte, 2048)
	var wg sync.WaitGroup
	writtenCh := make(chan int, numStreams)
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(w *streamWriter) {
			defer wg.Done()
			n, err := w.Write(body)
			if err != nil && err != errStreamClosed {
				t.Errorf("write error: %v", err)
			}
			writtenCh <- n
		}(writers[i])
	}

	// Wait briefly for writers to consume the window, then check.
	// Collect however many finished without blocking.
	var totalWritten int
	timeout := time.After(100 * time.Millisecond)
	for totalWritten < int(connWindow) {
		select {
		case n := <-writtenCh:
			totalWritten += n
		case <-timeout:
			goto done
		}
	}
done:

	// Total bytes written must not exceed the connection window.
	if totalWritten > int(connWindow) {
		t.Fatalf("concurrent writers exceeded connection window: wrote %d, window %d", totalWritten, connWindow)
	}

	// Connection window should reflect exactly what was consumed.
	remaining := server.connSendWindow.Load()
	if remaining < 0 {
		t.Fatalf("connection window went negative: %d", remaining)
	}
	if int32(totalWritten)+remaining != connWindow {
		t.Fatalf("accounting mismatch: written=%d remaining=%d window=%d", totalWritten, remaining, connWindow)
	}
}

// --- HEADERS on half-closed (remote) stream returns RST_STREAM, no panic ---

func TestHeadersOnHalfClosedRemoteStream(t *testing.T) {
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	stream, err := mgr.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	req := core.AcquireRequest()
	initRequest(req, core.MethodPost, "https://example.com/upload")
	req.Version = core.VersionHTTP2

	// Build initial HEADERS with END_STREAM so the request direction closes immediately.
	frames, err := mgr.BuildRequestHeaderFrames(stream.ID, req, true)
	core.ReleaseRequest(req)
	if err != nil {
		t.Fatalf("build frames: %v", err)
	}

	var frameBuf bytes.Buffer
	for _, frame := range frames {
		serialized := frame.Header.Serialize()
		frameBuf.Write(serialized[:])
		if len(frame.Payload) > 0 {
			frameBuf.Write(frame.Payload)
		}
	}

	// Build a second HEADERS+END_STREAM (illegal — request direction already closed).
	// Use the same stream manager to encode trailer headers.
	trailers := core.NewHeaders()
	trailers.SetString("X-Trailer", "value")
	trailerFrames, err := mgr.BuildTrailerFrames(stream.ID, &trailers, true)
	if err != nil {
		t.Fatalf("build trailer frames: %v", err)
	}
	for _, frame := range trailerFrames {
		serialized := frame.Header.Serialize()
		frameBuf.Write(serialized[:])
		if len(frame.Payload) > 0 {
			frameBuf.Write(frame.Payload)
		}
	}

	var discard bytes.Buffer
	server := NewServerSession(&frameBuf, &discard)

	// First ReadRequest should succeed (the initial HEADERS+END_STREAM).
	_, gotReq, err := server.ReadRequest()
	if err != nil {
		t.Fatalf("first ReadRequest: %v", err)
	}
	core.ReleaseRequest(gotReq)

	// Wait for readLoop to process the second HEADERS — it should produce
	// a connection error (RST_STREAM sent, readLoop may continue or exit).
	<-server.readLoopDone
}

// --- Malformed trailers must return decode error, not EOF ---

func TestMalformedTrailersReturnError(t *testing.T) {
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	stream, err := mgr.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	req := core.AcquireRequest()
	initRequest(req, core.MethodPost, "https://example.com/upload")
	req.Version = core.VersionHTTP2

	// Build request HEADERS without END_STREAM (body expected).
	frames, err := mgr.BuildRequestHeaderFrames(stream.ID, req, false)
	core.ReleaseRequest(req)
	if err != nil {
		t.Fatalf("build frames: %v", err)
	}

	var frameBuf bytes.Buffer
	for _, frame := range frames {
		serialized := frame.Header.Serialize()
		frameBuf.Write(serialized[:])
		if len(frame.Payload) > 0 {
			frameBuf.Write(frame.Payload)
		}
	}

	// DATA frame with body but NO END_STREAM.
	body := []byte("hello")
	dataHdr := FrameHeader{
		Length:   uint32(len(body)),
		Type:     FrameData,
		StreamID: stream.ID,
	}
	serialized := dataHdr.Serialize()
	frameBuf.Write(serialized[:])
	frameBuf.Write(body)

	// HEADERS+END_STREAM with illegal pseudo-header in trailers.
	// HPACK literal header field, never indexed (0x00):
	//   name_len(7) ":status" value_len(3) "200"
	// DecodeTrailerHeaderBlock rejects pseudo-headers.
	trailerPayload := []byte{
		0x00,
		0x07,
		':', 's', 't', 'a', 't', 'u', 's',
		0x03,
		'2', '0', '0',
	}
	trailerHdr := FrameHeader{
		Length:   uint32(len(trailerPayload)),
		Type:     FrameHeaders,
		Flags:    FlagEndStream | FlagEndHeaders,
		StreamID: stream.ID,
	}
	serialized = trailerHdr.Serialize()
	frameBuf.Write(serialized[:])
	frameBuf.Write(trailerPayload)

	var discard bytes.Buffer
	server := NewServerSession(&frameBuf, &discard)

	_, _, err = server.ReadRequest()
	if err == nil {
		t.Fatal("expected error from malformed trailers, got nil")
	}
	if err == io.EOF {
		t.Fatal("expected trailers decode error, got EOF — termErr not prioritized over dataCh close")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("pseudo")) {
		t.Fatalf("unexpected error message: %v", err)
	}
}
