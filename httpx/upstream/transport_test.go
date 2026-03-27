package upstream

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dnsoa/net/httpx/core"
	protohttp1 "github.com/dnsoa/net/httpx/protocol/http1"
	protohttp2 "github.com/dnsoa/net/httpx/protocol/http2"
	protohttp3 "github.com/dnsoa/net/httpx/protocol/http3"
)

func TestHTTP1TransportRoundTrip(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client := NewHTTP1Transport(protohttp1.NewConn(clientConn, clientConn))
	server := protohttp1.NewConn(serverConn, serverConn)
	defer server.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, err := server.ReadRequest()
		if err != nil {
			return
		}
		defer core.ReleaseRequest(req)
		resp := core.AcquireResponse()
		defer core.ReleaseResponse(resp)
		resp.Status = core.NewStatus(200)
		resp.Headers.SetString("x-upstream", "http1")
		resp.Body = append(resp.Body, []byte("ok-http1")...)
		_ = server.WriteResponse(resp)
	}()

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	if err := req.Init(core.MethodGet, "https://cdn.example.com/object"); err != nil {
		t.Fatalf("init request: %v", err)
	}
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer core.ReleaseResponse(resp)
	if string(resp.Body) != "ok-http1" {
		t.Fatalf("unexpected body %q", resp.Body)
	}
	wg.Wait()
}

func TestHTTP2TransportRoundTrip(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client := NewHTTP2Transport(protohttp2.NewClientSession(clientConn, clientConn))
	server := protohttp2.NewServerSession(serverConn, serverConn)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		streamID, req, err := server.ReadRequest()
		if err != nil {
			return
		}
		defer core.ReleaseRequest(req)
		resp := core.AcquireResponse()
		defer core.ReleaseResponse(resp)
		resp.Version = core.VersionHTTP2
		resp.Status = core.NewStatus(206)
		resp.Headers.SetString("x-upstream", "http2")
		resp.Body = append(resp.Body, []byte("ok-http2")...)
		_ = server.WriteResponse(streamID, resp)
	}()

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	if err := req.Init(core.MethodGet, "https://cdn.example.com/range.ts"); err != nil {
		t.Fatalf("init request: %v", err)
	}
	req.Version = core.VersionHTTP2
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer core.ReleaseResponse(resp)
	if resp.Status.Code != 206 {
		t.Fatalf("unexpected status %d", resp.Status.Code)
	}
	if string(resp.Body) != "ok-http2" {
		t.Fatalf("unexpected body %q", resp.Body)
	}
	wg.Wait()
}

type pipeStreamOpener struct {
	handler func(requestBytes []byte) ([]byte, error)
}

type countingRequestStreamOpener struct {
	inner     pipeStreamOpener
	openCalls atomic.Int32
}

type loopbackControlOpener struct {
	localWriter io.Writer
	remoteData  []byte
}

type countingControlOpener struct {
	inner       loopbackControlOpener
	openCalls   atomic.Int32
	acceptCalls atomic.Int32
}

func (o loopbackControlOpener) OpenControlStream() (io.Writer, error) {
	return o.localWriter, nil
}

func (o loopbackControlOpener) AcceptControlStream() (io.Reader, error) {
	return bytes.NewReader(o.remoteData), nil
}

func (o *countingControlOpener) OpenControlStream() (io.Writer, error) {
	o.openCalls.Add(1)
	return o.inner.OpenControlStream()
}

func (o *countingControlOpener) AcceptControlStream() (io.Reader, error) {
	o.acceptCalls.Add(1)
	return o.inner.AcceptControlStream()
}

func (o pipeStreamOpener) OpenRequestStream() (io.ReadWriter, error) {
	return &loopbackStream{handler: o.handler}, nil
}

func (o *countingRequestStreamOpener) OpenRequestStream() (io.ReadWriter, error) {
	o.openCalls.Add(1)
	return o.inner.OpenRequestStream()
}

type loopbackStream struct {
	request  bytes.Buffer
	response bytes.Reader
	handler  func(requestBytes []byte) ([]byte, error)
	built    bool
}

func (s *loopbackStream) Write(p []byte) (int, error) {
	if s.built {
		return 0, io.ErrClosedPipe
	}
	return s.request.Write(p)
}

func (s *loopbackStream) Read(p []byte) (int, error) {
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

func TestHTTP3TransportRoundTrip(t *testing.T) {
	clientSession := protohttp3.NewClientSession()
	serverSession := protohttp3.NewServerSession()

	var clientControl bytes.Buffer
	var serverControl bytes.Buffer
	serverBootstrapped := false
	if err := serverSession.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}

	transport := NewHTTP3Transport(protohttp3.NewTransport(
		clientSession,
		loopbackControlOpener{localWriter: &clientControl, remoteData: serverControl.Bytes()},
		pipeStreamOpener{handler: func(requestBytes []byte) ([]byte, error) {
			if !serverBootstrapped {
				if err := serverSession.ReadControlStream(bytes.NewReader(clientControl.Bytes())); err != nil {
					return nil, err
				}
				serverBootstrapped = true
			}
			req, err := serverSession.ReadRequest(bytes.NewReader(requestBytes))
			if err != nil {
				return nil, err
			}
			defer core.ReleaseRequest(req)
			resp := core.AcquireResponse()
			defer core.ReleaseResponse(resp)
			resp.Version = core.VersionHTTP3
			resp.Status = core.NewStatus(200)
			resp.Headers.SetString("x-upstream", "http3")
			resp.Body = append(resp.Body, []byte("ok-http3")...)
			var response bytes.Buffer
			if err := serverSession.WriteResponse(&response, resp); err != nil {
				return nil, err
			}
			return response.Bytes(), nil
		}},
	))

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	if err := req.Init(core.MethodGet, "https://cdn.example.com/live/playlist.m3u8"); err != nil {
		t.Fatalf("init request: %v", err)
	}
	req.Version = core.VersionHTTP3
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer core.ReleaseResponse(resp)
	if string(resp.Body) != "ok-http3" {
		t.Fatalf("unexpected body %q", resp.Body)
	}
}

func TestHTTP3TransportConcurrentRoundTrip(t *testing.T) {
	const requestCount = 8

	clientSession := protohttp3.NewClientSession()
	serverSession := protohttp3.NewServerSession()

	var clientControl bytes.Buffer
	var serverControl bytes.Buffer
	var serverBootstrap sync.Once
	var serverBootstrapErr error
	var releaseHandlers sync.Once
	var enteredHandlers atomic.Int32
	handlerGate := make(chan struct{})

	if err := serverSession.WriteControlStream(&serverControl); err != nil {
		t.Fatalf("write server control stream: %v", err)
	}

	controlOpener := &countingControlOpener{
		inner: loopbackControlOpener{localWriter: &clientControl, remoteData: serverControl.Bytes()},
	}
	requestOpener := &countingRequestStreamOpener{}
	requestOpener.inner = pipeStreamOpener{handler: func(requestBytes []byte) ([]byte, error) {
		serverBootstrap.Do(func() {
			serverBootstrapErr = serverSession.ReadControlStream(bytes.NewReader(clientControl.Bytes()))
		})
		if serverBootstrapErr != nil {
			return nil, serverBootstrapErr
		}

		if enteredHandlers.Add(1) == requestCount {
			releaseHandlers.Do(func() {
				close(handlerGate)
			})
		}
		<-handlerGate

		req, err := serverSession.ReadRequest(bytes.NewReader(requestBytes))
		if err != nil {
			return nil, err
		}
		defer core.ReleaseRequest(req)

		requestID := string(req.Headers.Get("x-request-id"))
		resp := core.AcquireResponse()
		defer core.ReleaseResponse(resp)
		resp.Version = core.VersionHTTP3
		resp.Status = core.NewStatus(200)
		resp.Headers.SetString("x-upstream", "http3")
		resp.Headers.SetString("x-request-id", requestID)
		resp.Body = append(resp.Body, []byte(fmt.Sprintf("ok-http3-%s", requestID))...)

		var response bytes.Buffer
		if err := serverSession.WriteResponse(&response, resp); err != nil {
			return nil, err
		}
		return response.Bytes(), nil
	}}
	transport := NewHTTP3Transport(protohttp3.NewTransport(
		clientSession,
		controlOpener,
		requestOpener,
	))

	var wg sync.WaitGroup
	errCh := make(chan error, requestCount)

	for i := 0; i < requestCount; i++ {
		requestID := strconv.Itoa(i)
		wg.Add(1)
		go func(requestID string) {
			defer wg.Done()
			req := core.AcquireRequest()
			defer core.ReleaseRequest(req)
			if err := req.Init(core.MethodGet, "https://cdn.example.com/segment/"+requestID+".m4s"); err != nil {
				errCh <- err
				return
			}
			req.Version = core.VersionHTTP3
			req.Headers.SetString("x-request-id", requestID)

			resp, err := transport.RoundTrip(req)
			if err != nil {
				errCh <- err
				return
			}
			defer core.ReleaseResponse(resp)

			if got := string(resp.Headers.Get("x-request-id")); got != requestID {
				errCh <- fmt.Errorf("unexpected response header id %q", got)
				return
			}
			if got := string(resp.Body); got != "ok-http3-"+requestID {
				errCh <- fmt.Errorf("unexpected response body %q", got)
				return
			}
		}(requestID)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	if got := controlOpener.openCalls.Load(); got != 1 {
		t.Fatalf("unexpected open control calls %d", got)
	}
	if got := controlOpener.acceptCalls.Load(); got != 1 {
		t.Fatalf("unexpected accept control calls %d", got)
	}
	if got := requestOpener.openCalls.Load(); got != requestCount {
		t.Fatalf("unexpected request stream open calls %d", got)
	}
	if got := enteredHandlers.Load(); got != requestCount {
		t.Fatalf("expected all request handlers to enter the barrier, got %d", got)
	}
}
