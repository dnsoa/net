package core

import (
	"bytes"
	"io"
	"testing"

	"github.com/dnsoa/go/allocator"
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

func TestRequestHost(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)
	if err := req.Init(MethodGet, "https://example.com:8443/path"); err != nil {
		t.Fatalf("init: %v", err)
	}
	if got := string(req.Host()); got != "example.com" {
		t.Fatalf("unexpected host %q", got)
	}
}

func TestRequestHostFromHeader(t *testing.T) {
	req := AcquireRequest()
	defer ReleaseRequest(req)
	if err := req.Init(MethodGet, "/path"); err != nil {
		t.Fatalf("init: %v", err)
	}
	req.Headers.SetString("Host", "from-header.com")
	if got := string(req.Host()); got != "from-header.com" {
		t.Fatalf("unexpected host %q", got)
	}
}

func TestResponseSetJSONBody(t *testing.T) {
	resp := AcquireResponse()
	defer ReleaseResponse(resp)
	if err := resp.SetJSONBody(map[string]string{"status": "ok"}); err != nil {
		t.Fatalf("set json body: %v", err)
	}
	if resp.ContentLength == 0 {
		t.Fatal("expected non-zero content length")
	}
	if !resp.OK() {
		t.Fatal("expected OK")
	}
}

func TestRequestAllocatorPropagation(t *testing.T) {
	alloc := allocator.New()
	req := AcquireRequest()
	req.SetAllocator(alloc)

	req.Init(MethodPost, "https://example.com/api")
	req.Headers.SetString("content-type", "application/json")

	ReleaseRequest(req)
}

func TestResponseAllocatorPropagation(t *testing.T) {
	alloc := allocator.New()
	resp := AcquireResponse()
	resp.SetAllocator(alloc)

	resp.Status = NewStatus(200)
	resp.Headers.SetString("content-type", "application/json")

	ReleaseResponse(resp)
}

func TestRequestAllocatorSurvivesReset(t *testing.T) {
	alloc := allocator.New()
	req := AcquireRequest()
	req.SetAllocator(alloc)
	req.Headers.SetString("x-test", "value")

	req.Reset()

	if req.alloc != alloc {
		t.Fatal("allocator lost after reset")
	}

	ReleaseRequest(req)
}

func TestResponseAllocatorSurvivesReset(t *testing.T) {
	alloc := allocator.New()
	resp := AcquireResponse()
	resp.SetAllocator(alloc)
	resp.Headers.SetString("x-test", "value")

	resp.Reset()

	if resp.alloc != alloc {
		t.Fatal("allocator lost after reset")
	}

	ReleaseResponse(resp)
}

// ============================================================================
// Headers benchmarks: with vs without allocator
// ============================================================================

func BenchmarkHeadersAppend_NoAllocator(b *testing.B) {
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

func BenchmarkHeadersAppend_WithAllocator(b *testing.B) {
	alloc := allocator.New()
	h := NewHeaders()
	h.SetAllocator(alloc)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.AppendString("Content-Type", "application/json")
		h.AppendString("Content-Length", "1234")
		h.AppendString("Connection", "keep-alive")
		h.AppendString("Cache-Control", "no-cache")
		h.Reset()
	}
}

func BenchmarkHeadersGet_NoAllocator(b *testing.B) {
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

func BenchmarkHeadersGet_WithAllocator(b *testing.B) {
	alloc := allocator.New()
	h := NewHeaders()
	h.SetAllocator(alloc)
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

// ============================================================================
// URI benchmarks: with vs without allocator
// ============================================================================

func BenchmarkURIParse_NoAllocator(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		uri := URI{Path: []byte("/")}
		uri.ParseString("https://cdn.example.com:8443/video/seg.ts?token=abc#section")
		uri.Reset()
	}
}

func BenchmarkURIParse_WithAllocator(b *testing.B) {
	alloc := allocator.New()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		uri := URI{Path: []byte("/")}
		uri.SetAllocator(alloc)
		uri.ParseString("https://cdn.example.com:8443/video/seg.ts?token=abc#section")
		uri.Reset()
	}
}

// ============================================================================
// Request benchmarks: with vs without allocator (full request lifecycle)
// ============================================================================

func BenchmarkRequestInit_NoAllocator(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := AcquireRequest()
		req.Init(MethodPost, "https://cdn.example.com:8443/api/data?key=search")
		req.Headers.SetString("content-type", "application/json")
		req.Headers.SetString("x-trace-id", "abc-123")
		ReleaseRequest(req)
	}
}

func BenchmarkRequestInit_WithAllocator(b *testing.B) {
	alloc := allocator.New()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := AcquireRequest()
		req.SetAllocator(alloc)
		req.Init(MethodPost, "https://cdn.example.com:8443/api/data?key=search")
		req.Headers.SetString("content-type", "application/json")
		req.Headers.SetString("x-trace-id", "abc-123")
		ReleaseRequest(req)
	}
}

// ============================================================================
// Response benchmarks: with vs without allocator (full response lifecycle)
// ============================================================================

func BenchmarkResponseLifecycle_NoAllocator(b *testing.B) {
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

func BenchmarkResponseLifecycle_WithAllocator(b *testing.B) {
	alloc := allocator.New()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp := AcquireResponse()
		resp.SetAllocator(alloc)
		resp.Status = NewStatus(200)
		resp.Headers.SetString("Content-Type", "application/json")
		resp.Headers.SetString("X-Cache-Status", "HIT")
		resp.SetBody(io.NopCloser(bytes.NewReader([]byte(`{"status":"ok"}`))))
		ReleaseResponse(resp)
	}
}
