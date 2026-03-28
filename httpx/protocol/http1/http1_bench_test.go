package http1

import (
	"bytes"
	"io"
	"testing"

	"github.com/dnsoa/net/httpx/core"
)

func nopCloser(b []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(b))
}

// Benchmark formatting a simple GET request
func BenchmarkFormatRequestSimple(b *testing.B) {
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	req.Init(core.MethodGet, "https://example.com/api")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 0, 256)
		_ = FormatRequest(req, nil, buf)
	}
}

// Benchmark formatting a POST request with body
func BenchmarkFormatRequestWithBody(b *testing.B) {
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	req.Init(core.MethodPost, "https://example.com/api")
	req.SetBody(nopCloser([]byte(`{"name":"test","value":"data"}`)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 0, 512)
		_ = FormatRequest(req, nil, buf)
	}
}

// Benchmark formatting a chunked request
func BenchmarkFormatRequestChunked(b *testing.B) {
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	req.Init(core.MethodPost, "https://example.com/upload")
	req.Headers.Set(core.HeaderTransferEncoding, []byte("chunked"))
	req.Body = nopCloser(make([]byte, 8192)) // 8KB body
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 0, 16384)
		_ = FormatRequest(req, buf, nil)
	}
}

// Benchmark formatting a response
func BenchmarkFormatResponseSimple(b *testing.B) {
	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Status = core.NewStatus(200)
	resp.SetBody(nopCloser([]byte("OK")))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 0, 256)
		_ = FormatResponse(resp, buf, nil)
	}
}

// Benchmark formatting a JSON response
func BenchmarkFormatResponseJSON(b *testing.B) {
	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Status = core.NewStatus(200)
	resp.SetJSONBody(map[string]string{"status": "ok", "data": "test"})
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 0, 512)
		_ = FormatResponse(resp, nil, buf)
	}
}

// Benchmark reading a request from connection
func BenchmarkConnReadRequest(b *testing.B) {
	input := []byte("GET /api/v1/resource?id=123 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Accept: application/json\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn := NewConn(bytes.NewReader(input), nil)
		req, _ := conn.ReadRequest()
		core.ReleaseRequest(req)
		conn.Close()
	}
}

// Benchmark reading a response from connection
func BenchmarkConnReadResponse(b *testing.B) {
	input := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 27\r\n" +
		"\r\n" +
		`{"status":"ok","data":{}}`)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn := NewConn(bytes.NewReader(input), nil)
		resp, _ := conn.ReadResponse()
		core.ReleaseResponse(resp)
		conn.Close()
	}
}

// Benchmark writing a request
func BenchmarkConnWriteRequest(b *testing.B) {
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	req.Init(core.MethodGet, "https://example.com/api")
	req.Headers.SetString("Accept", "application/json")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		conn := NewConn(nil, &buf)
		_ = conn.WriteRequest(req)
	}
}

// Benchmark writing a response
func BenchmarkConnWriteResponse(b *testing.B) {
	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Status = core.NewStatus(200)
	resp.SetBody(nopCloser([]byte(`{"result":"success"}`)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		conn := NewConn(nil, &buf)
		_ = conn.WriteResponse(resp)
	}
}

// Benchmark round-trip (write request, read response)
func BenchmarkConnRoundTrip(b *testing.B) {
	response := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 2\r\n" +
		"\r\n" +
		"OK")
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	req.Init(core.MethodGet, "https://example.com/ping")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		conn := NewConn(bytes.NewReader(response), &buf)
		_ = conn.WriteRequest(req)
		resp, _ := conn.ReadResponse()
		core.ReleaseResponse(resp)
		conn.Close()
	}
}

// Benchmark chunked body formatting
func BenchmarkAppendChunkedBody(b *testing.B) {
	body := make([]byte, 16384) // 16KB
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 0, 32768)
		trailers := core.NewHeaders()
		buf = appendChunkedBody(buf, body, &trailers)
	}
}

// Benchmark connection reuse simulation
func BenchmarkConnKeepAlive(b *testing.B) {
	requests := []byte(
		"GET /1 HTTP/1.1\r\nHost: example.com\r\n\r\n" +
			"GET /2 HTTP/1.1\r\nHost: example.com\r\n\r\n" +
			"GET /3 HTTP/1.1\r\nHost: example.com\r\n\r\n" +
			"GET /4 HTTP/1.1\r\nHost: example.com\r\n\r\n" +
			"GET /5 HTTP/1.1\r\nHost: example.com\r\n\r\n",
	)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn := NewConn(bytes.NewReader(requests), nil)
		for j := 0; j < 5; j++ {
			req, _ := conn.ReadRequest()
			core.ReleaseRequest(req)
		}
		conn.Close()
	}
}

// Benchmark reading chunked response
func BenchmarkConnReadChunkedResponse(b *testing.B) {
	body := make([]byte, 4096)
	var chunked bytes.Buffer
	chunked.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
	chunked.WriteString("1000\r\n") // 4096 in hex
	chunked.Write(body)
	chunked.WriteString("\r\n0\r\n\r\n")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn := NewConn(bytes.NewReader(chunked.Bytes()), nil)
		resp, _ := conn.ReadResponse()
		core.ReleaseResponse(resp)
		conn.Close()
	}
}
