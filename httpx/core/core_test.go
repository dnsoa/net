package core

import (
	"bytes"
	"testing"
)

func TestHeadersCaseInsensitive(t *testing.T) {
	h := NewHeaders()
	defer h.Reset()
	h.AppendString("Content-Type", "application/json")
	if got := string(h.Get("content-type")); got != "application/json" {
		t.Fatalf("unexpected header value %q", got)
	}
}

func TestURIParse(t *testing.T) {
	uri, err := ParseURI("https://example.com:8443/search?q=zig#frag")
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	defer uri.Reset()
	if string(uri.Scheme) != "https" {
		t.Fatalf("unexpected scheme %q", uri.Scheme)
	}
	if string(uri.Host) != "example.com" {
		t.Fatalf("unexpected host %q", uri.Host)
	}
	if uri.EffectivePort() != 8443 {
		t.Fatalf("unexpected port %d", uri.EffectivePort())
	}
}

func TestRequestSerialize(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)
	if err := req.Init(MethodGet, "https://example.com/api"); err != nil {
		t.Fatalf("init request: %v", err)
	}
	encoded := req.Serialize(nil)
	if !bytes.HasPrefix(encoded, []byte("GET /api HTTP/1.1\r\n")) {
		t.Fatalf("unexpected request serialization %q", encoded)
	}
}

func TestResponseSerialize(t *testing.T) {
	resp := AcquireResponse()
	defer ReleaseResponse(resp)
	resp.Status = NewStatus(200)
	encoded := resp.Serialize(nil)
	if !bytes.HasPrefix(encoded, []byte("HTTP/1.1 200 OK\r\n")) {
		t.Fatalf("unexpected response serialization %q", encoded)
	}
}
