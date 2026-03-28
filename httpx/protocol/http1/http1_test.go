package http1

import (
	"bytes"
	"io"
	"testing"

	"github.com/dnsoa/net/httpx/core"
	rootprotocol "github.com/dnsoa/net/httpx/protocol"
)

func TestFormatRequestAddsContentLength(t *testing.T) {
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	if err := req.Init(core.MethodPost, "https://example.com/upload"); err != nil {
		t.Fatalf("init request: %v", err)
	}
	req.SetBody(io.NopCloser(bytes.NewReader([]byte("hello"))))
	body, _ := req.ReadAll()
	encoded := FormatRequest(req, body, nil)
	if !bytes.Contains(encoded, []byte("Content-Length: 5\r\n")) {
		t.Fatalf("missing content-length in request: %q", encoded)
	}
}

func TestConnReadRequest(t *testing.T) {
	input := bytes.NewBufferString("GET /ping HTTP/1.1\r\nHost: example.com\r\n\r\n")
	conn := NewConn(input, nil)
	defer conn.Close()

	msg, err := conn.readMessage(rootprotocol.ParserModeRequest)
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	req := msg.(*core.Request)
	defer core.ReleaseRequest(req)
	if string(req.URI.Path) != "/ping" {
		t.Fatalf("unexpected request path %q", req.URI.Path)
	}
}

func TestConnReadResponse(t *testing.T) {
	input := bytes.NewBufferString("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	conn := NewConn(input, nil)
	defer conn.Close()

	resp, err := conn.ReadResponse()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer core.ReleaseResponse(resp)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("unexpected response body %q", body)
	}
}

func TestConnWriteResponse(t *testing.T) {
	var out bytes.Buffer
	conn := NewConn(nil, &out)
	defer conn.Close()

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Status = core.NewStatus(200)
	resp.SetBody(io.NopCloser(bytes.NewReader([]byte("ok"))))

	if err := conn.WriteResponse(resp); err != nil {
		t.Fatalf("write response: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("Content-Length: 2\r\n")) {
		t.Fatalf("missing content-length in response: %q", out.Bytes())
	}
}

func TestFormatResponseChunked(t *testing.T) {
	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Status = core.NewStatus(200)
	resp.Headers.Set(core.HeaderTransferEncoding, []byte("chunked"))
	resp.SetBody(io.NopCloser(bytes.NewReader([]byte("hello"))))
	resp.Trailers.SetString("x-cache", "hit")

	body, _ := resp.ReadAll()
	encoded := FormatResponse(resp, body, nil)
	if bytes.Contains(encoded, []byte("Content-Length:")) {
		t.Fatalf("content-length should be omitted for chunked response: %q", encoded)
	}
	if !bytes.Contains(encoded, []byte("Trailer: x-cache\r\n")) {
		t.Fatalf("missing trailer declaration: %q", encoded)
	}
	if !bytes.Contains(encoded, []byte("5\r\nhello\r\n0\r\nx-cache: hit\r\n\r\n")) {
		t.Fatalf("invalid chunked response body: %q", encoded)
	}
}

func TestFormatRequestChunkedWithTrailers(t *testing.T) {
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	if err := req.Init(core.MethodPost, "https://example.com/upload"); err != nil {
		t.Fatalf("init request: %v", err)
	}
	req.Headers.Set(core.HeaderTransferEncoding, []byte("chunked"))
	req.SetBody(io.NopCloser(bytes.NewReader([]byte("hello"))))
	req.Trailers.SetString("x-origin-status", "stale")

	body, _ := req.ReadAll()
	encoded := FormatRequest(req, body, nil)
	if !bytes.Contains(encoded, []byte("Trailer: x-origin-status\r\n")) {
		t.Fatalf("missing trailer declaration: %q", encoded)
	}
	if !bytes.Contains(encoded, []byte("x-origin-status: stale\r\n\r\n")) {
		t.Fatalf("missing trailer payload: %q", encoded)
	}
}

func TestConnReadResponseKeepAliveFalse(t *testing.T) {
	input := bytes.NewBufferString("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
	conn := NewConn(input, nil)
	defer conn.Close()

	resp, err := conn.ReadResponse()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer core.ReleaseResponse(resp)
	if conn.ShouldKeepAlive() {
		t.Fatal("expected keep-alive to be disabled")
	}
}

func TestConnReadRequestKeepAliveHTTP10(t *testing.T) {
	input := bytes.NewBufferString("GET /ping HTTP/1.0\r\nHost: example.com\r\n\r\n")
	conn := NewConn(input, nil)
	defer conn.Close()

	req, err := conn.ReadRequest()
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	defer core.ReleaseRequest(req)
	if conn.ShouldKeepAlive() {
		t.Fatal("expected http/1.0 request without keep-alive header to disable connection reuse")
	}
}
