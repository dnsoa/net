package http2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/dnsoa/net/httpx/core"
)

// newTestServerSession creates a server session without H2 connection preface handshake.
// Use this for unit tests that don't need real I/O.
func newTestServerSession(reader io.Reader, writer io.Writer) *Session {
	conn := NewConn(reader, writer)
	conn.IsClient = false
	conn.NextStreamID = 2
	return newSession(conn, false)
}

func readTestFrames(t *testing.T, data []byte) []Frame {
	t.Helper()
	reader := bytes.NewReader(data)
	conn := NewConn(reader, nil)
	frames := make([]Frame, 0, 4)
	for reader.Len() > 0 {
		frame, err := conn.ReadFrame(1 << 20)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		frames = append(frames, frame)
	}
	return frames
}

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
	s := newTestServerSession(nil, nil)
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

func TestBroadcastErrorSkipsHalfClosedRemote(t *testing.T) {
	s := newTestServerSession(nil, nil)
	ss := s.registerStream(1, stateHalfClosedRemote)

	testErr := errors.New("received GOAWAY")
	s.broadcastError(testErr)

	if ss.closed.Load() {
		t.Fatal("expected half-closed remote stream to remain writable")
	}
	select {
	case err := <-ss.errCh:
		t.Fatalf("did not expect error for half-closed remote stream, got %v", err)
	default:
	}
}

// --- streamReader with nil dataCh returns EOF ---

func TestStreamReaderNilDataCh(t *testing.T) {
	sr := &streamReader{
		dataCh:            nil,
		session:           newTestServerSession(nil, nil),
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
		session:           newTestServerSession(nil, nil),
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

func TestStreamReaderSendsConnectionWindowUpdate(t *testing.T) {
	var written bytes.Buffer
	s := newTestServerSession(nil, &written)
	ss := s.registerStream(1, stateOpen)
	body := bytes.Repeat([]byte("a"), 40000)

	s.handleDataFrame(Frame{
		Header: FrameHeader{
			Length:   uint32(len(body)),
			Type:     FrameData,
			Flags:    FlagEndStream,
			StreamID: 1,
		},
		Payload: body,
	})

	sr := &streamReader{
		dataCh:            ss.dataCh,
		errCh:             ss.errCh,
		session:           s,
		streamID:          1,
		recvWindow:        65535,
		initialWindowSize: 65535,
		ss:                ss,
	}

	if _, err := io.Copy(io.Discard, sr); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got := s.connRecvWindow.Load(); got != 65535 {
		t.Fatalf("expected connection receive window to reset, got %d", got)
	}

	frames := readTestFrames(t, written.Bytes())
	var sawStreamWindowUpdate bool
	var sawConnWindowUpdate bool
	for _, frame := range frames {
		if frame.Header.Type != FrameWindowUpdate {
			continue
		}
		switch frame.Header.StreamID {
		case 0:
			sawConnWindowUpdate = true
		case 1:
			sawStreamWindowUpdate = true
		}
	}
	if !sawStreamWindowUpdate {
		t.Fatal("expected stream WINDOW_UPDATE")
	}
	if !sawConnWindowUpdate {
		t.Fatal("expected connection WINDOW_UPDATE")
	}
}

func TestHandleDataFramePaddedStripsPadding(t *testing.T) {
	s := newTestServerSession(nil, nil)
	ss := s.registerStream(1, stateOpen)
	payload := []byte{2, 'a', 'b', 'c', 0, 0}

	s.handleDataFrame(Frame{
		Header: FrameHeader{
			Length:   uint32(len(payload)),
			Type:     FrameData,
			Flags:    FlagPadded | FlagEndStream,
			StreamID: 1,
		},
		Payload: payload,
	})

	sr := &streamReader{
		dataCh:            ss.dataCh,
		errCh:             ss.errCh,
		session:           s,
		streamID:          1,
		recvWindow:        65535,
		initialWindowSize: 65535,
		ss:                ss,
	}

	body, err := io.ReadAll(sr)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "abc" {
		t.Fatalf("unexpected body %q", string(body))
	}
	if s.readLoopErr != nil {
		t.Fatalf("unexpected connection error: %v", s.readLoopErr)
	}
}

func TestHandleDataFramePaddedRejectsInvalidPadding(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "empty payload",
			payload: nil,
		},
		{
			name:    "padding exceeds payload",
			payload: []byte{4, 'a', 'b'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServerSession(nil, nil)
			s.registerStream(1, stateOpen)

			s.handleDataFrame(Frame{
				Header: FrameHeader{
					Length:   uint32(len(tt.payload)),
					Type:     FrameData,
					Flags:    FlagPadded,
					StreamID: 1,
				},
				Payload: tt.payload,
			})

			if s.readLoopErr == nil {
				t.Fatal("expected connection error")
			}
		})
	}
}

// --- streamReader error propagation ---

func TestStreamReaderError(t *testing.T) {
	dataCh := make(chan []byte, 1)
	errCh := make(chan error, 1)

	sr := &streamReader{
		dataCh:            dataCh,
		errCh:             errCh,
		session:           newTestServerSession(nil, nil),
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

func TestHandleHeaderFrameRSTOnDecodeRequestError(t *testing.T) {
	var written bytes.Buffer
	s := newTestServerSession(nil, &written)

	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
	} {
		if err := enc.WriteField(field); err != nil {
			t.Fatalf("encode header field: %v", err)
		}
	}

	s.handleHeaderFrame(Frame{
		Header: FrameHeader{
			Length:   uint32(block.Len()),
			Type:     FrameHeaders,
			Flags:    FlagEndHeaders | FlagEndStream,
			StreamID: 1,
		},
		Payload: block.Bytes(),
	})

	if s.getStreamState(1) != nil {
		t.Fatal("expected invalid request stream to remain unregistered")
	}
	frames := readTestFrames(t, written.Bytes())
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if frames[0].Header.Type != FrameRSTStream {
		t.Fatalf("expected RST_STREAM, got %v", frames[0].Header.Type)
	}
	if frames[0].Header.StreamID != 1 {
		t.Fatalf("expected stream 1 reset, got %d", frames[0].Header.StreamID)
	}
}

func TestHandleDataFrameUnknownStreamFailsConnection(t *testing.T) {
	s := newTestServerSession(nil, nil)

	s.handleDataFrame(Frame{
		Header:  FrameHeader{Length: 1, Type: FrameData, StreamID: 1},
		Payload: []byte{"x"[0]},
	})

	if s.readLoopErr == nil {
		t.Fatal("expected connection error for unknown stream data")
	}
}

func TestHandleWindowUpdateFrameRejectsInvalidPayload(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
	}{
		{
			name: "short payload",
			frame: Frame{
				Header:  FrameHeader{Length: 3, Type: FrameWindowUpdate, StreamID: 0},
				Payload: []byte{0, 0, 1},
			},
		},
		{
			name: "zero increment",
			frame: Frame{
				Header:  FrameHeader{Length: 4, Type: FrameWindowUpdate, StreamID: 0},
				Payload: []byte{0, 0, 0, 0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServerSession(nil, nil)
			s.handleWindowUpdateFrame(tt.frame)
			if s.readLoopErr == nil {
				t.Fatal("expected connection error")
			}
		})
	}
}

// --- streamState concurrent access ---

func TestStreamStateConcurrentAccess(t *testing.T) {
	s := newTestServerSession(nil, nil)
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
	s := newTestServerSession(nil, nil)
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
	s := newTestServerSession(nil, nil)
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
	server := newTestServerSession(&frameBuf, &discard)

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
	server := newTestServerSession(&frameBuf, &discard)

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
	server := newTestServerSession(nil, &out)
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
	server := newTestServerSession(nil, &out)
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

func TestWriteResponseAfterBroadcastErrorOnHalfClosedRemote(t *testing.T) {
	var out bytes.Buffer
	server := newTestServerSession(nil, &out)
	server.conn = NewConn(nil, &out)
	server.registerStream(1, stateHalfClosedRemote)

	server.broadcastError(errors.New("http2: received GOAWAY"))

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP2
	resp.Status = core.NewStatus(200)
	resp.Headers.SetString("Content-Type", "text/plain")
	resp.SetBody(io.NopCloser(bytes.NewReader([]byte("OK"))))

	if err := server.WriteResponse(1, resp); err != nil {
		t.Fatalf("write response after GOAWAY broadcast: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("expected output bytes after GOAWAY broadcast")
	}
	if server.getStreamState(1) != nil {
		t.Fatal("expected stream to be unregistered after response completes")
	}
}

// --- WriteResponseHead returns nil for no-body ---

func TestWriteResponseHeadNoBody(t *testing.T) {
	var out bytes.Buffer
	server := newTestServerSession(nil, &out)
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
	server := newTestServerSession(&frameBuf, &discard)

	_, _, err = server.ReadRequest()
	if err == nil {
		t.Fatal("expected error after RST_STREAM")
	}
}

// --- WINDOW_UPDATE parsing ---

func TestWindowUpdateFrameParsing(t *testing.T) {
	s := newTestServerSession(nil, nil)
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
	server := newTestServerSession(nil, &out)
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
	s := newTestServerSession(nil, nil)

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
	s := newTestServerSession(nil, nil)

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
	s := newTestServerSession(nil, nil)
	ss := s.registerStream(1, stateOpen)
	if cap(ss.dataCh) != dataChCapacity {
		t.Fatalf("unexpected dataCh capacity %d, want %d", cap(ss.dataCh), dataChCapacity)
	}
}

// --- sendWindow initialization ---

func TestSendWindowInitialization(t *testing.T) {
	settings := DefaultConnectionSettings()
	settings.InitialWindowSize = 32768
	s := newTestServerSession(nil, nil)
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
	server := newTestServerSession(nil, &out)
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
			if err != nil && err != ErrStreamClosedWrite {
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
	server := newTestServerSession(&frameBuf, &discard)

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
	server := newTestServerSession(&frameBuf, &discard)

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
