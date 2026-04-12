package core

import (
	"bytes"
	"io"
	"testing"
)

func initRequest(req *Request, method Method, rawURL string) {
	req.Method = method
	req.Version = VersionHTTP11
	req.URI.ParseString(rawURL)
	if len(req.URI.Host) > 0 {
		req.Headers.Set(HeaderHost, req.URI.Host)
	}
}

func TestHeadersCaseInsensitive(t *testing.T) {
	h := NewHeaders()
	defer h.Reset()
	h.AppendString("Content-Type", "application/json")
	if got := string(h.Get("content-type")); got != "application/json" {
		t.Fatalf("unexpected header value %q", got)
	}
}

func TestHeadersCloneIsolation(t *testing.T) {
	h := NewHeaders()
	defer h.Reset()
	h.AppendString("Content-Type", "application/json")
	h.AppendString("X-Test", "original")

	clone := h.Clone()
	defer clone.Reset()
	clone.SetString("X-Test", "mutated")

	if got := string(h.Get("X-Test")); got != "original" {
		t.Fatalf("unexpected original header value %q", got)
	}
	if got := string(clone.Get("X-Test")); got != "mutated" {
		t.Fatalf("unexpected cloned header value %q", got)
	}
}

func TestHeadersCloneResetAndRemoveAll(t *testing.T) {
	h := NewHeaders()
	defer h.Reset()
	h.AppendString("Content-Type", "text/plain")
	h.AppendString("Cache-Control", "max-age=60")
	h.AppendString("X-Test", "value")

	clone := h.Clone()
	clone.RemoveAllString("Cache-Control")
	if got := clone.Get("Cache-Control"); got != nil {
		t.Fatalf("expected cache-control removed, got %q", got)
	}
	clone.Reset()
}

func TestHeadersCloneRemoveAllPreservesRemainingEntries(t *testing.T) {
	h := NewHeaders()
	defer h.Reset()
	h.AppendString("Content-Type", "text/plain")
	h.AppendString("Cache-Control", "max-age=60")
	h.AppendString("ETag", "bench-tag")

	clone := h.Clone()
	defer clone.Reset()
	clone.RemoveAllString("Cache-Control")
	clone.SetString("X-New", "value")

	if got := string(clone.Get("Content-Type")); got != "text/plain" {
		t.Fatalf("unexpected content-type after remove: %q", got)
	}
	if got := string(clone.Get("ETag")); got != "bench-tag" {
		t.Fatalf("unexpected etag after remove: %q", got)
	}
	if got := clone.Get("Cache-Control"); got != nil {
		t.Fatalf("expected cache-control removed, got %q", got)
	}
	if got := string(clone.Get("X-New")); got != "value" {
		t.Fatalf("unexpected x-new after insert: %q", got)
	}
	if got := string(h.Get("ETag")); got != "bench-tag" {
		t.Fatalf("unexpected original etag after clone mutation: %q", got)
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

func TestRequestHost(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)
	initRequest(req, MethodGet, "https://example.com:8443/path")
	if got := string(req.Host()); got != "example.com" {
		t.Fatalf("unexpected host %q", got)
	}
}

func TestRequestHostFromHeader(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)
	req.Method = MethodGet
	req.URI.ParseString("/path")
	req.Headers.SetString("Host", "from-header.com")
	if got := string(req.Host()); got != "from-header.com" {
		t.Fatalf("unexpected host %q", got)
	}
}

func TestResponseLifecycle(t *testing.T) {
	resp := AcquireResponse()
	defer ReleaseResponse(resp)
	resp.Status = NewStatus(200)
	resp.Headers.SetString("Content-Type", "application/json")
	body := []byte(`{"status":"ok"}`)
	resp.SetBody(io.NopCloser(bytes.NewReader(body)))
	resp.ContentLength = int64(len(body))
	if resp.ContentLength == 0 {
		t.Fatal("expected non-zero content length")
	}
}

func TestRequestLifecycle(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)
	initRequest(req, MethodPost, "https://example.com/api")
	req.Headers.SetString("content-type", "application/json")
}

func TestContainsTokenCIAcceptsHTABOWS(t *testing.T) {
	tests := []struct {
		name     string
		haystack []byte
		needle   []byte
		want     bool
	}{
		{name: "chunked with tab", haystack: []byte("gzip,\tchunked"), needle: []byte("chunked"), want: true},
		{name: "keep-alive with tabs", haystack: []byte("\tkeep-alive\t"), needle: []byte("keep-alive"), want: true},
		{name: "close with mixed ows", haystack: []byte("keep-alive, \tclose\t"), needle: []byte("close"), want: true},
		{name: "token boundary preserved", haystack: []byte("gzip,\tchunkedx"), needle: []byte("chunked"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsTokenCI(tt.haystack, tt.needle); got != tt.want {
				t.Fatalf("ContainsTokenCI(%q, %q) = %v, want %v", tt.haystack, tt.needle, got, tt.want)
			}
		})
	}
}

// ============================================================================
// Headers benchmarks
// ============================================================================

func BenchmarkHeadersAppend(b *testing.B) {
	h := NewHeaders()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.AppendString("Content-Type", "application/json")
		h.AppendString("Content-Length", "1234")
		h.AppendString("Connection", "keep-alive")
		h.AppendString("Cache-Control", "no-cache")
		h.Reset()
	}
}

func BenchmarkHeadersGet(b *testing.B) {
	h := NewHeaders()
	h.AppendString("Content-Type", "application/json")
	h.AppendString("Content-Length", "1234")
	h.AppendString("X-Custom-Header", "custom-value")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Get("content-type")
		h.Get("Content-Length")
		h.Get("X-CUSTOM-HEADER")
	}
}

func BenchmarkHeadersClone(b *testing.B) {
	h := NewHeaders()
	h.AppendString("Content-Type", "application/json")
	h.AppendString("Content-Length", "1234")
	h.AppendString("Cache-Control", "public, max-age=300")
	h.AppendString("ETag", "abc123")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		clone := h.Clone()
		clone.Reset()
	}
	h.Reset()
}

// ============================================================================
// URI benchmarks
// ============================================================================

func BenchmarkURIParse(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		uri := URI{Path: []byte("/")}
		uri.ParseString("https://cdn.example.com:8443/video/seg.ts?token=abc#section")
		uri.Reset()
	}
}

// ============================================================================
// Request benchmarks: full request lifecycle
// ============================================================================

func BenchmarkRequestInit(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := AcquireRequest()
		initRequest(req, MethodPost, "https://cdn.example.com:8443/api/data?key=search")
		req.Headers.SetString("content-type", "application/json")
		req.Headers.SetString("x-trace-id", "abc-123")
		ReleaseRequest(req)
	}
}

// ============================================================================
// Response benchmarks: full response lifecycle
// ============================================================================

func BenchmarkResponseLifecycle(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp := AcquireResponse()
		resp.Status = NewStatus(200)
		resp.Headers.SetString("Content-Type", "application/json")
		resp.Headers.SetString("X-Cache-Status", "HIT")
		resp.SetBody(io.NopCloser(bytes.NewReader([]byte(`{"status":"ok"}`))))
		ReleaseResponse(resp)
	}
}
