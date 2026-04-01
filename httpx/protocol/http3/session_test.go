package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/dnsoa/net/httpx/core"
)

type testControlOpener struct {
	localWriter io.Writer
	remoteData  []byte
}

func (o testControlOpener) OpenControlStream() (io.Writer, error) {
	return o.localWriter, nil
}

func (o testControlOpener) AcceptControlStream() (io.Reader, error) {
	return bytes.NewReader(o.remoteData), nil
}

type lifecycleTestStream struct {
	request          bytes.Buffer
	response         []byte
	readOffset       int
	blockReads       bool
	unblockRead      chan struct{}
	writeClosed      chan struct{}
	readCancelErr    error
	closeWriteCalls  atomic.Int32
	closeReadCalls   atomic.Int32
	closeCalls       atomic.Int32
	cancelReadCalls  atomic.Int32
	cancelWriteCalls atomic.Int32
	builtResponse    atomic.Bool
}

func newLifecycleTestStream(response []byte) *lifecycleTestStream {
	return &lifecycleTestStream{
		response:    response,
		unblockRead: make(chan struct{}),
		writeClosed: make(chan struct{}),
	}
}

func (s *lifecycleTestStream) Write(p []byte) (int, error) {
	return s.request.Write(p)
}

func (s *lifecycleTestStream) Read(p []byte) (int, error) {
	if s.blockReads {
		<-s.unblockRead
		if s.readCancelErr != nil {
			return 0, s.readCancelErr
		}
	}
	if s.readOffset >= len(s.response) {
		return 0, io.EOF
	}
	n := copy(p, s.response[s.readOffset:])
	s.readOffset += n
	return n, nil
}

func (s *lifecycleTestStream) CloseWrite() error {
	s.closeWriteCalls.Add(1)
	select {
	case <-s.writeClosed:
	default:
		close(s.writeClosed)
	}
	return nil
}

func (s *lifecycleTestStream) CloseRead() error {
	s.closeReadCalls.Add(1)
	return nil
}

func (s *lifecycleTestStream) Close() error {
	s.closeCalls.Add(1)
	select {
	case <-s.unblockRead:
	default:
		close(s.unblockRead)
	}
	return nil
}

func (s *lifecycleTestStream) CancelRead(code ErrorCode) error {
	_ = code
	s.cancelReadCalls.Add(1)
	select {
	case <-s.unblockRead:
	default:
		close(s.unblockRead)
	}
	return nil
}

func (s *lifecycleTestStream) CancelWrite(code ErrorCode) error {
	_ = code
	s.cancelWriteCalls.Add(1)
	return nil
}

type lifecycleStreamOpener struct {
	stream *lifecycleTestStream
}

func (o lifecycleStreamOpener) OpenRequestStream() (io.ReadWriter, error) {
	return o.stream, nil
}

type qpackLoopbackOpener struct {
	clientToServerEncoder bytes.Buffer
	serverToClientEncoder bytes.Buffer
	clientToServerDecoder bytes.Buffer
	serverToClientDecoder bytes.Buffer
	serverControl         []byte
	clientControl         bytes.Buffer
}

func (o *qpackLoopbackOpener) OpenControlStream() (io.Writer, error) {
	o.clientControl.Reset()
	return &o.clientControl, nil
}

func (o *qpackLoopbackOpener) AcceptControlStream() (io.Reader, error) {
	return bytes.NewReader(o.serverControl), nil
}

func (o *qpackLoopbackOpener) OpenEncoderStream() (io.Writer, error) {
	o.clientToServerEncoder.Reset()
	return &o.clientToServerEncoder, nil
}

func (o *qpackLoopbackOpener) AcceptEncoderStream() (io.Reader, error) {
	if o.serverToClientEncoder.Len() == 0 {
		return nil, nil
	}
	data := append([]byte(nil), o.serverToClientEncoder.Bytes()...)
	o.serverToClientEncoder.Reset()
	return bytes.NewReader(data), nil
}

func (o *qpackLoopbackOpener) OpenDecoderStream() (io.Writer, error) {
	o.clientToServerDecoder.Reset()
	return &o.clientToServerDecoder, nil
}

func (o *qpackLoopbackOpener) AcceptDecoderStream() (io.Reader, error) {
	if o.serverToClientDecoder.Len() == 0 {
		return nil, nil
	}
	data := append([]byte(nil), o.serverToClientDecoder.Bytes()...)
	o.serverToClientDecoder.Reset()
	return bytes.NewReader(data), nil
}

type qpackRoundTripLoopbackStream struct {
	request     bytes.Buffer
	response    bytes.Reader
	built       bool
	handler     func(requestBytes []byte) ([]byte, error)
	closeWrites atomic.Int32
	closeReads  atomic.Int32
	closes      atomic.Int32
}

func (s *qpackRoundTripLoopbackStream) Write(p []byte) (int, error) {
	if s.built {
		return 0, io.ErrClosedPipe
	}
	return s.request.Write(p)
}

func (s *qpackRoundTripLoopbackStream) Read(p []byte) (int, error) {
	if !s.built {
		response, err := s.handler(append([]byte(nil), s.request.Bytes()...))
		if err != nil {
			return 0, err
		}
		s.response = *bytes.NewReader(response)
		s.built = true
	}
	return s.response.Read(p)
}

func (s *qpackRoundTripLoopbackStream) CloseWrite() error {
	s.closeWrites.Add(1)
	return nil
}

func (s *qpackRoundTripLoopbackStream) CloseRead() error {
	s.closeReads.Add(1)
	return nil
}

func (s *qpackRoundTripLoopbackStream) Close() error {
	s.closes.Add(1)
	return nil
}

type qpackRoundTripStreamOpener struct {
	streams []*qpackRoundTripLoopbackStream
	handler func(requestBytes []byte) ([]byte, error)
}

func (o *qpackRoundTripStreamOpener) OpenRequestStream() (io.ReadWriter, error) {
	stream := &qpackRoundTripLoopbackStream{handler: o.handler}
	o.streams = append(o.streams, stream)
	return stream, nil
}

func TestSettingsRoundTrip(t *testing.T) {
	settings := Settings{MaxFieldSectionSize: 65535, QPACKMaxTableCap: 4096, QPACKBlockedStreams: 32}
	encoded, err := EncodeSettings(settings, nil)
	if err != nil {
		t.Fatalf("encode settings: %v", err)
	}
	decoded, err := DecodeSettings(encoded)
	if err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if decoded != settings {
		t.Fatalf("unexpected decoded settings %+v", decoded)
	}
}

func TestQpackRequestResponseRoundTrip(t *testing.T) {
	codec := NewQpackCodec()
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodGet, "https://example.com/video/seg.ts?part=1")
	req.Headers.SetString("accept-encoding", "gzip, deflate, br")
	req.Headers.SetString("x-cache-key", "video:seg")
	block, err := codec.EncodeRequest(req)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	decodedReq, err := codec.DecodeRequest(block)
	if err != nil {
		t.Fatalf("decode request: %v", err)
	}
	defer core.ReleaseRequest(decodedReq)
	if decodedReq.Method != core.MethodGet {
		t.Fatalf("unexpected method %v", decodedReq.Method)
	}
	if string(decodedReq.URI.Path) != "/video/seg.ts" {
		t.Fatalf("unexpected path %q", decodedReq.URI.Path)
	}
	if string(decodedReq.Headers.Get("x-cache-key")) != "video:seg" {
		t.Fatalf("unexpected header %q", decodedReq.Headers.Get("x-cache-key"))
	}

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP3
	resp.Status = core.NewStatus(206)
	resp.Headers.SetString("content-type", "video/mp2t")
	respBlock, err := codec.EncodeResponse(resp)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	decodedResp, err := codec.DecodeResponse(respBlock)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	defer core.ReleaseResponse(decodedResp)
	if decodedResp.Status.Code != 206 {
		t.Fatalf("unexpected status %d", decodedResp.Status.Code)
	}
}

func TestQpackDynamicTableRoundTrip(t *testing.T) {
	encoder := NewQpackCodec()
	decoder := NewQpackCodec()
	encoder.SetLocalCapacity(256)
	decoder.SetRemoteCapacity(256)

	firstBlock, err := encoder.EncodeFields([]HeaderField{{Name: "x-cache-key", Value: "video:seg:1"}})
	if err != nil {
		t.Fatalf("encode first block: %v", err)
	}
	encoderStream := encoder.DrainEncoderInstructions()
	if len(encoderStream) == 0 {
		t.Fatal("expected encoder instructions for first block")
	}
	if err := decoder.ApplyEncoderInstructions(encoderStream); err != nil {
		t.Fatalf("apply encoder instructions: %v", err)
	}
	decodedFirst, err := decoder.DecodeFields(firstBlock)
	if err != nil {
		t.Fatalf("decode first block: %v", err)
	}
	if len(decodedFirst) != 1 || decodedFirst[0].Name != "x-cache-key" || decodedFirst[0].Value != "video:seg:1" {
		t.Fatalf("unexpected first decode %+v", decodedFirst)
	}
	decoderStream := decoder.DrainDecoderInstructions()
	if len(decoderStream) == 0 {
		t.Fatal("expected decoder instructions after first decode")
	}
	if err := encoder.ApplyDecoderInstructions(decoderStream); err != nil {
		t.Fatalf("apply decoder instructions: %v", err)
	}

	secondBlock, err := encoder.EncodeFields([]HeaderField{{Name: "x-cache-key", Value: "video:seg:1"}})
	if err != nil {
		t.Fatalf("encode second block: %v", err)
	}
	if len(secondBlock) < 3 || secondBlock[2]&0x80 == 0 || secondBlock[2]&0x40 != 0 {
		t.Fatalf("expected dynamic indexed field in second block: %v", secondBlock)
	}
	if err := decoder.ApplyEncoderInstructions(encoder.DrainEncoderInstructions()); err != nil {
		t.Fatalf("apply second encoder instructions: %v", err)
	}
	decodedSecond, err := decoder.DecodeFields(secondBlock)
	if err != nil {
		t.Fatalf("decode second block: %v", err)
	}
	if len(decodedSecond) != 1 || decodedSecond[0].Value != "video:seg:1" {
		t.Fatalf("unexpected second decode %+v", decodedSecond)
	}
}

func TestSessionControlAndMessageRoundTrip(t *testing.T) {
	client := NewClientSession()
	server := NewServerSession()
	client.Settings = Settings{MaxFieldSectionSize: 65535, QPACKMaxTableCap: 4096, QPACKBlockedStreams: 64}

	var clientControl bytes.Buffer
	if err := client.WriteControlStream(&clientControl); err != nil {
		t.Fatalf("write control stream: %v", err)
	}
	if err := server.ReadControlStream(bytes.NewReader(clientControl.Bytes())); err != nil {
		t.Fatalf("read control stream: %v", err)
	}
	if server.PeerSettings.QPACKBlockedStreams != 64 {
		t.Fatalf("unexpected peer settings %+v", server.PeerSettings)
	}

	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	if err := client.ReadControlStream(bytes.NewReader(serverControl.Bytes())); err != nil {
		t.Fatalf("read server control stream: %v", err)
	}

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodPost, "https://origin.example.com/cache/fill?id=1")
	req.SetBody(io.NopCloser(bytes.NewReader([]byte("chunk-a"))))
	req.Trailers.SetString("x-origin-etag", "abc")

	var requestStream bytes.Buffer
	if err := client.WriteRequest(&requestStream, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	decodedReq, err := server.ReadRequest(bytes.NewReader(requestStream.Bytes()))
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	defer core.ReleaseRequest(decodedReq)
	decodedBody, err := io.ReadAll(decodedReq.Body)
	if err != nil {
		t.Fatalf("read decoded request body: %v", err)
	}
	if string(decodedBody) != "chunk-a" {
		t.Fatalf("unexpected request body %q", decodedBody)
	}
	if string(decodedReq.Trailers.Get("x-origin-etag")) != "abc" {
		t.Fatalf("unexpected request trailer %q", decodedReq.Trailers.Get("x-origin-etag"))
	}

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP3
	resp.Status = core.NewStatus(200)
	resp.Headers.SetString("content-type", "application/octet-stream")
	resp.SetBody(io.NopCloser(bytes.NewReader([]byte("payload"))))
	resp.Trailers.SetString("x-cache", "hit")

	var responseStream bytes.Buffer
	if err := server.WriteResponse(&responseStream, resp); err != nil {
		t.Fatalf("write response: %v", err)
	}
	decodedResp, err := client.ReadResponse(bytes.NewReader(responseStream.Bytes()))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer core.ReleaseResponse(decodedResp)
	if decodedResp.Status.Code != 200 {
		t.Fatalf("unexpected response status %d", decodedResp.Status.Code)
	}
	if string(decodedResp.Trailers.Get("x-cache")) != "hit" {
		t.Fatalf("unexpected response trailer %q", decodedResp.Trailers.Get("x-cache"))
	}
	respBody, err := io.ReadAll(decodedResp.Body)
	if err != nil {
		t.Fatalf("read decoded response body: %v", err)
	}
	if string(respBody) != "payload" {
		t.Fatalf("unexpected response body %q", respBody)
	}
}

func TestSessionQpackStreamsRoundTrip(t *testing.T) {
	client := NewClientSession()
	server := NewServerSession()
	client.Settings = Settings{MaxFieldSectionSize: 65535, QPACKMaxTableCap: 256, QPACKBlockedStreams: 16}
	server.Settings = Settings{MaxFieldSectionSize: 65535, QPACKMaxTableCap: 256, QPACKBlockedStreams: 16}

	var clientControl bytes.Buffer
	if err := client.WriteControlStream(&clientControl); err != nil {
		t.Fatalf("write client control stream: %v", err)
	}
	if err := server.ReadControlStream(bytes.NewReader(clientControl.Bytes())); err != nil {
		t.Fatalf("read client control stream: %v", err)
	}
	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	if err := client.ReadControlStream(bytes.NewReader(serverControl.Bytes())); err != nil {
		t.Fatalf("read server control stream: %v", err)
	}

	makeRequest := func() *core.Request {
		req := core.AcquireRequest()
		initRequest(req, core.MethodGet, "https://origin.example.com/cache/item.ts")
		req.Headers.SetString("x-cache-key", "asset:42")
		return req
	}

	firstReq := makeRequest()
	defer core.ReleaseRequest(firstReq)
	var firstRequestStream bytes.Buffer
	if err := client.WriteRequest(&firstRequestStream, firstReq); err != nil {
		t.Fatalf("write first request: %v", err)
	}
	var encoderStream bytes.Buffer
	if err := client.WriteEncoderStream(&encoderStream); err != nil {
		t.Fatalf("write encoder stream: %v", err)
	}
	if encoderStream.Len() == 0 {
		t.Fatal("expected non-empty qpack encoder stream")
	}
	if err := server.ReadEncoderStream(bytes.NewReader(encoderStream.Bytes())); err != nil {
		t.Fatalf("read encoder stream: %v", err)
	}
	decodedFirstReq, err := server.ReadRequest(bytes.NewReader(firstRequestStream.Bytes()))
	if err != nil {
		t.Fatalf("read first request: %v", err)
	}
	defer core.ReleaseRequest(decodedFirstReq)
	if string(decodedFirstReq.Headers.Get("x-cache-key")) != "asset:42" {
		t.Fatalf("unexpected first request header %q", decodedFirstReq.Headers.Get("x-cache-key"))
	}
	var decoderStream bytes.Buffer
	if err := server.WriteDecoderStream(&decoderStream); err != nil {
		t.Fatalf("write decoder stream: %v", err)
	}
	if decoderStream.Len() == 0 {
		t.Fatal("expected non-empty qpack decoder stream")
	}
	if err := client.ReadDecoderStream(bytes.NewReader(decoderStream.Bytes())); err != nil {
		t.Fatalf("read decoder stream: %v", err)
	}

	secondReq := makeRequest()
	defer core.ReleaseRequest(secondReq)
	var secondRequestStream bytes.Buffer
	if err := client.WriteRequest(&secondRequestStream, secondReq); err != nil {
		t.Fatalf("write second request: %v", err)
	}
	if secondRequestStream.Len() >= firstRequestStream.Len() {
		t.Fatalf("expected second request stream to benefit from dynamic qpack: first=%d second=%d", firstRequestStream.Len(), secondRequestStream.Len())
	}
	var secondEncoderStream bytes.Buffer
	if err := client.WriteEncoderStream(&secondEncoderStream); err != nil {
		t.Fatalf("write second encoder stream: %v", err)
	}
	if secondEncoderStream.Len() != 0 {
		t.Fatalf("expected no additional encoder instructions, got %d bytes", secondEncoderStream.Len())
	}
	decodedSecondReq, err := server.ReadRequest(bytes.NewReader(secondRequestStream.Bytes()))
	if err != nil {
		t.Fatalf("read second request: %v", err)
	}
	defer core.ReleaseRequest(decodedSecondReq)
	if string(decodedSecondReq.Headers.Get("x-cache-key")) != "asset:42" {
		t.Fatalf("unexpected second request header %q", decodedSecondReq.Headers.Get("x-cache-key"))
	}
}

func TestTransportRoundTripLifecycleClosesStream(t *testing.T) {
	client := NewClientSession()
	server := NewServerSession()

	var clientControl bytes.Buffer
	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	if err := client.WriteControlStream(&clientControl); err != nil {
		t.Fatalf("write client control stream: %v", err)
	}
	if err := server.ReadControlStream(bytes.NewReader(clientControl.Bytes())); err != nil {
		t.Fatalf("server read client control stream: %v", err)
	}
	if err := client.ReadControlStream(bytes.NewReader(serverControl.Bytes())); err != nil {
		t.Fatalf("client read server control stream: %v", err)
	}

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP3
	resp.Status = core.NewStatus(200)
	resp.SetBody(io.NopCloser(bytes.NewReader([]byte("ok"))))
	var response bytes.Buffer
	if err := server.WriteResponse(&response, resp); err != nil {
		t.Fatalf("write response: %v", err)
	}

	stream := newLifecycleTestStream(response.Bytes())
	transport := NewTransport(
		client,
		testControlOpener{localWriter: &clientControl, remoteData: serverControl.Bytes()},
		lifecycleStreamOpener{stream: stream},
	)
	transport.bootstrapped = true

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodGet, "https://cdn.example.com/object")
	gotResp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer core.ReleaseResponse(gotResp)
	gotBody, err := io.ReadAll(gotResp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(gotBody) != "ok" {
		t.Fatalf("unexpected response body %q", gotBody)
	}
	if got := stream.closeWriteCalls.Load(); got != 1 {
		t.Fatalf("unexpected close write calls %d", got)
	}
	if got := stream.closeReadCalls.Load(); got != 1 {
		t.Fatalf("unexpected close read calls %d", got)
	}
	if got := stream.closeCalls.Load(); got != 1 {
		t.Fatalf("unexpected close calls %d", got)
	}
	if got := stream.cancelWriteCalls.Load(); got != 0 {
		t.Fatalf("unexpected cancel write calls %d", got)
	}
	if got := stream.cancelReadCalls.Load(); got != 0 {
		t.Fatalf("unexpected cancel read calls %d", got)
	}
}

func TestTransportRoundTripContextCancelsStream(t *testing.T) {
	client := NewClientSession()
	server := NewServerSession()

	var clientControl bytes.Buffer
	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	if err := client.WriteControlStream(&clientControl); err != nil {
		t.Fatalf("write client control stream: %v", err)
	}
	if err := server.ReadControlStream(bytes.NewReader(clientControl.Bytes())); err != nil {
		t.Fatalf("server read client control stream: %v", err)
	}
	if err := client.ReadControlStream(bytes.NewReader(serverControl.Bytes())); err != nil {
		t.Fatalf("client read server control stream: %v", err)
	}

	stream := newLifecycleTestStream(nil)
	stream.blockReads = true
	stream.readCancelErr = errors.New("stream canceled")
	transport := NewTransport(
		client,
		testControlOpener{localWriter: &clientControl, remoteData: serverControl.Bytes()},
		lifecycleStreamOpener{stream: stream},
	)
	transport.bootstrapped = true

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodGet, "https://cdn.example.com/cancel-me")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		_, err := transport.RoundTripContext(ctx, req)
		errCh <- err
	}()
	<-stream.writeClosed
	cancel()
	err := <-errCh
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
	if got := stream.cancelWriteCalls.Load(); got == 0 {
		t.Fatal("expected cancel write to be called")
	}
	if got := stream.cancelReadCalls.Load(); got == 0 {
		t.Fatal("expected cancel read to be called")
	}
	if got := stream.closeCalls.Load(); got != 1 {
		t.Fatalf("unexpected close calls %d", got)
	}
}

func TestTransportRoundTripIntegratesQPACKStreams(t *testing.T) {
	client := NewClientSession()
	server := NewServerSession()
	client.Settings = Settings{MaxFieldSectionSize: 65535, QPACKMaxTableCap: 256, QPACKBlockedStreams: 16}
	server.Settings = Settings{MaxFieldSectionSize: 65535, QPACKMaxTableCap: 256, QPACKBlockedStreams: 16}

	var serverControl bytes.Buffer
	if err := server.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}
	opener := &qpackLoopbackOpener{serverControl: append([]byte(nil), serverControl.Bytes()...)}
	streamOpener := &qpackRoundTripStreamOpener{}

	var serverSeenClientControl bool
	streamOpener.handler = func(requestBytes []byte) ([]byte, error) {
		if !serverSeenClientControl {
			if err := server.ReadControlStream(bytes.NewReader(opener.clientControl.Bytes())); err != nil {
				return nil, err
			}
			serverSeenClientControl = true
		}
		if opener.clientToServerEncoder.Len() > 0 {
			if err := server.ReadEncoderStream(bytes.NewReader(opener.clientToServerEncoder.Bytes())); err != nil {
				return nil, err
			}
			opener.clientToServerEncoder.Reset()
		}
		req, err := server.ReadRequest(bytes.NewReader(requestBytes))
		if err != nil {
			return nil, err
		}
		defer core.ReleaseRequest(req)
		if err := server.WriteDecoderStream(&opener.serverToClientDecoder); err != nil {
			return nil, err
		}

		resp := core.AcquireResponse()
		defer core.ReleaseResponse(resp)
		resp.Version = core.VersionHTTP3
		resp.Status = core.NewStatus(200)
		resp.Headers.SetString("x-cache-node", "edge-1")
		resp.Headers.SetString("x-cache-key", string(req.Headers.Get("x-cache-key")))
		resp.SetBody(io.NopCloser(bytes.NewReader([]byte("ok"))))

		var response bytes.Buffer
		if err := server.WriteResponse(&response, resp); err != nil {
			return nil, err
		}
		if err := server.WriteEncoderStream(&opener.serverToClientEncoder); err != nil {
			return nil, err
		}
		return response.Bytes(), nil
	}

	transport := NewTransport(client, opener, streamOpener)

	makeRequest := func() *core.Request {
		req := core.AcquireRequest()
		initRequest(req, core.MethodGet, "https://cdn.example.com/video/seg.ts")
		req.Version = core.VersionHTTP3
		req.Headers.SetString("x-cache-key", "asset:42")
		req.Headers.SetString("x-origin-name", "origin-a")
		return req
	}

	firstReq := makeRequest()
	firstResp, err := transport.RoundTrip(firstReq)
	if err != nil {
		core.ReleaseRequest(firstReq)
		t.Fatalf("first round trip: %v", err)
	}
	core.ReleaseRequest(firstReq)
	core.ReleaseResponse(firstResp)

	secondReq := makeRequest()
	secondResp, err := transport.RoundTrip(secondReq)
	if err != nil {
		core.ReleaseRequest(secondReq)
		t.Fatalf("second round trip: %v", err)
	}
	core.ReleaseRequest(secondReq)
	core.ReleaseResponse(secondResp)

	if len(streamOpener.streams) != 2 {
		t.Fatalf("expected 2 opened request streams, got %d", len(streamOpener.streams))
	}
	firstLen := streamOpener.streams[0].request.Len()
	secondLen := streamOpener.streams[1].request.Len()
	if secondLen >= firstLen {
		t.Fatalf("expected second request to use qpack dynamic references: first=%d second=%d", firstLen, secondLen)
	}
	if streamOpener.streams[0].closeWrites.Load() == 0 || streamOpener.streams[1].closeWrites.Load() == 0 {
		t.Fatal("expected transport to close write side for both request streams")
	}
	if opener.clientToServerDecoder.Len() == 0 {
		t.Fatal("expected client decoder stream to be written after response decode")
	}
}
