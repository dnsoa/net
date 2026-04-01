package http3

import (
	"testing"

	"github.com/dnsoa/net/httpx/core"
)

func initRequest(req *core.Request, method core.Method, rawURL string) {
	req.Method = method
	req.Version = core.VersionHTTP11
	req.URI.ParseString(rawURL)
	if len(req.URI.Host) > 0 {
		req.Headers.Set(core.HeaderHost, req.URI.Host)
	}
}

// Benchmark variable-length integer encoding
func BenchmarkAppendVarInt(b *testing.B) {
	values := []uint64{25, 15293, 494878333, 151288809941952652}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, v := range values {
			_, _ = AppendVarInt(nil, v)
		}
	}
}

// Benchmark variable-length integer decoding
func BenchmarkDecodeVarInt(b *testing.B) {
	testCases := []struct {
		value uint64
	}{
		{25},
		{15293},
		{494878333},
		{151288809941952652},
	}
	inputs := make([][]byte, len(testCases))
	for i, tc := range testCases {
		inputs[i], _ = AppendVarInt(nil, tc.value)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			_, _, _ = DecodeVarInt(input)
		}
	}
}

// Benchmark frame header encoding
func BenchmarkFrameHeaderEncode(b *testing.B) {
	headers := []FrameHeader{
		{Type: uint64(FrameData), Length: 16384},
		{Type: uint64(FrameHeaders), Length: 4096},
		{Type: uint64(FrameSettings), Length: 0},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, h := range headers {
			_, _ = h.Encode(nil)
		}
	}
}

// Benchmark frame header decoding
func BenchmarkDecodeFrameHeader(b *testing.B) {
	encoded := make([][]byte, 3)
	encoded[0], _ = FrameHeader{Type: uint64(FrameData), Length: 16384}.Encode(nil)
	encoded[1], _ = FrameHeader{Type: uint64(FrameHeaders), Length: 4096}.Encode(nil)
	encoded[2], _ = FrameHeader{Type: uint64(FrameSettings), Length: 0}.Encode(nil)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, e := range encoded {
			_, _, _ = DecodeFrameHeader(e)
		}
	}
}

// Benchmark QPACK encoding request headers
func BenchmarkQpackEncodeRequest(b *testing.B) {
	codec := NewQpackCodec()
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodPost, "https://example.com/api")
	req.Headers.SetString("content-type", "application/json")
	req.Headers.SetString("authorization", "Bearer token")
	req.Headers.SetString("x-request-id", "abc-123")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = codec.EncodeRequest(req)
	}
}

// Benchmark QPACK encoding response headers
func BenchmarkQpackEncodeResponse(b *testing.B) {
	codec := NewQpackCodec()
	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Status = core.NewStatus(200)
	resp.Headers.SetString("content-type", "application/json")
	resp.Headers.SetString("content-length", "1234")
	resp.Headers.SetString("x-cache-status", "hit")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = codec.EncodeResponse(resp)
	}
}

// Benchmark QPACK decoding request headers
func BenchmarkQpackDecodeRequest(b *testing.B) {
	codec := NewQpackCodec()
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodGet, "https://example.com/api")
	req.Headers.SetString("user-agent", "Mozilla/5.0")
	req.Headers.SetString("accept", "application/json")
	encoded, _ := codec.EncodeRequest(req)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decoded, _ := codec.DecodeRequest(encoded)
		core.ReleaseRequest(decoded)
	}
}

// Benchmark QPACK decoding response headers
func BenchmarkQpackDecodeResponse(b *testing.B) {
	codec := NewQpackCodec()
	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Status = core.NewStatus(200)
	resp.Headers.SetString("content-type", "text/html")
	resp.Headers.SetString("content-length", "4096")
	encoded, _ := codec.EncodeResponse(resp)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decoded, _ := codec.DecodeResponse(encoded)
		core.ReleaseResponse(decoded)
	}
}

// Benchmark QPACK with dynamic table
func BenchmarkQpackDynamicTableEncoding(b *testing.B) {
	codec := NewQpackCodec()
	codec.SetLocalCapacity(4096)
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodPost, "https://example.com/api")
	req.Headers.SetString("x-custom-header-1", "value1")
	req.Headers.SetString("x-custom-header-2", "value2")
	req.Headers.SetString("x-custom-header-3", "value3")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = codec.EncodeRequest(req)
	}
}

// Benchmark QPACK static table lookup
func BenchmarkQpackStaticTableLookup(b *testing.B) {
	// Common headers that should hit static table
	fields := [][]HeaderField{
		{{Name: ":method", Value: "GET"}},
		{{Name: ":scheme", Value: "https"}},
		{{Name: ":authority", Value: "example.com"}},
		{{Name: ":path", Value: "/"}},
		{{Name: "accept", Value: "*/*"}},
		{{Name: "user-agent", Value: "Mozilla/5.0"}},
	}
	codec := NewQpackCodec()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, field := range fields {
			_, _ = codec.EncodeFields(field)
		}
	}
}

// Benchmark prefixed integer encoding
func BenchmarkAppendPrefixedInt(b *testing.B) {
	values := []uint64{10, 100, 1000, 10000, 100000}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, v := range values {
			_ = appendPrefixedInt(nil, 6, 0xC0, v)
		}
	}
}

// Benchmark prefixed integer decoding
func BenchmarkDecodePrefixedInt(b *testing.B) {
	inputs := make([][]byte, 5)
	for i, v := range []uint64{10, 100, 1000, 10000, 100000} {
		inputs[i] = appendPrefixedInt(nil, 6, 0xC0, v)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			_, _, _ = decodePrefixedInt(input, 6)
		}
	}
}

// Benchmark QPACK string encoding
func BenchmarkAppendQpackString(b *testing.B) {
	strings := []string{
		"application/json",
		"text/html;charset=utf-8",
		"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, s := range strings {
			_ = appendQpackString(nil, s)
		}
	}
}

// Benchmark QPACK string decoding
func BenchmarkDecodeQpackString(b *testing.B) {
	strings := []string{
		"application/json",
		"text/html;charset=utf-8",
		"Bearer token123456789",
		"User-Agent-String-Here",
	}
	inputs := make([][]byte, len(strings))
	for i, s := range strings {
		inputs[i] = appendQpackString(nil, s)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			_, _, _ = decodeQpackString(input)
		}
	}
}
