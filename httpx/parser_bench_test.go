package httpx_test

import (
	"testing"

	"github.com/dnsoa/net/httpx/core"
	"github.com/dnsoa/net/httpx/protocol"
)

// Benchmark HTTP/1.1 request parsing
func BenchmarkParserHTTPRequest(b *testing.B) {
	input := []byte("GET /search?q=test&page=1 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Accept: application/json\r\n" +
		"Content-Length: 13\r\n" +
		"\r\n" +
		"Hello, World!")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p := protocol.AcquireParser(protocol.ParserModeRequest)
		p.Feed(input)
		req, _ := p.BuildRequest()
		core.ReleaseRequest(req)
		protocol.ReleaseParser(p)
	}
}

// Benchmark HTTP/1.1 response parsing
func BenchmarkParserHTTPResponse(b *testing.B) {
	input := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 27\r\n" +
		"\r\n" +
		`{"status":"ok","data":{}}`)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p := protocol.AcquireParser(protocol.ParserModeResponse)
		p.Feed(input)
		resp, _ := p.BuildResponse()
		core.ReleaseResponse(resp)
		protocol.ReleaseParser(p)
	}
}

// Benchmark chunked response parsing
func BenchmarkParserHTTPChunkedResponse(b *testing.B) {
	input := []byte("HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"5\r\n" +
		"Hello\r\n" +
		"6\r\n" +
		" World\r\n" +
		"0\r\n" +
		"\r\n")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p := protocol.AcquireParser(protocol.ParserModeResponse)
		p.Feed(input)
		resp, _ := p.BuildResponse()
		core.ReleaseResponse(resp)
		protocol.ReleaseParser(p)
	}
}

// Benchmark incremental parsing (simulating streaming)
func BenchmarkParserIncrementalRequest(b *testing.B) {
	chunks := [][]byte{
		[]byte("GET /api/v1/"),
		[]byte("resource?id=123 HTTP/1.1\r\n"),
		[]byte("Host: example.com\r\n"),
		[]byte("Authorization: Bearer token\r\n"),
		[]byte("Content-Length: 4\r\n"),
		[]byte("\r\n"),
		[]byte("test"),
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p := protocol.AcquireParser(protocol.ParserModeRequest)
		for _, chunk := range chunks {
			p.Feed(chunk)
		}
		req, _ := p.BuildRequest()
		core.ReleaseRequest(req)
		protocol.ReleaseParser(p)
	}
}

// Benchmark parsing with many headers
func BenchmarkParserRequestWithManyHeaders(b *testing.B) {
	input := []byte("GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Accept: */*\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Cache-Control: no-cache\r\n" +
		"Connection: keep-alive\r\n" +
		"Cookie: session=abc123; user_id=456\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Referer: https://example.com\r\n" +
		"X-Request-ID: abc-123-def\r\n" +
		"X-Forwarded-For: 1.2.3.4\r\n" +
		"X-Real-IP: 1.2.3.4\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p := protocol.AcquireParser(protocol.ParserModeRequest)
		p.Feed(input)
		req, _ := p.BuildRequest()
		core.ReleaseRequest(req)
		protocol.ReleaseParser(p)
	}
}

// Benchmark header operations
func BenchmarkHeadersAppend(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h := core.NewHeaders()
		h.AppendString("Content-Type", "application/json")
		h.AppendString("Content-Length", "1234")
		h.AppendString("Connection", "keep-alive")
		h.AppendString("Cache-Control", "no-cache")
		h.Reset()
	}
}

func BenchmarkHeadersGet(b *testing.B) {
	h := core.NewHeaders()
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
