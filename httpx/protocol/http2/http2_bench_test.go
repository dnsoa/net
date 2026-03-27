package http2

import (
	"testing"

	"github.com/dnsoa/net/httpx/core"
)

// Benchmark HTTP/2 frame header encoding
func BenchmarkFrameHeaderSerialize(b *testing.B) {
	hdr := FrameHeader{
		Length:   16384,
		Type:     FrameData,
		Flags:    FlagEndStream,
		StreamID: 1,
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = hdr.Serialize()
	}
}

// Benchmark HTTP/2 frame header decoding
func BenchmarkParseFrameHeader(b *testing.B) {
	hdr := FrameHeader{
		Length:   16384,
		Type:     FrameData,
		Flags:    FlagEndStream,
		StreamID: 1,
	}
	serialized := hdr.Serialize()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ParseFrameHeader(serialized)
	}
}

// Benchmark building request header frames
func BenchmarkStreamManagerBuildRequestHeaders(b *testing.B) {
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	req.Init(core.MethodPost, "https://example.com/api")
	req.Headers.SetString("content-type", "application/json")
	req.Headers.SetString("authorization", "Bearer token123")
	req.Headers.SetString("x-request-id", "abc-123-def")
	stream, _ := mgr.OpenStream()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		frames, _ := mgr.BuildRequestHeaderFrames(stream.ID, req, true)
		// Reset for next iteration
		for _, f := range frames {
			f.Payload = nil
		}
	}
}

// Benchmark building response header frames
func BenchmarkStreamManagerBuildResponseHeaders(b *testing.B) {
	mgr := NewStreamManager(false, DefaultConnectionSettings(), DefaultConnectionSettings())
	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Status = core.NewStatus(200)
	resp.Headers.SetString("content-type", "application/json")
	resp.Headers.SetString("content-length", "1234")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = mgr.BuildResponseHeaderFrames(1, resp, true)
	}
}

// Benchmark building data frames with splitting
func BenchmarkStreamManagerBuildDataFrames(b *testing.B) {
	peerSettings := DefaultConnectionSettings()
	peerSettings.MaxFrameSize = 4096
	mgr := NewStreamManager(true, DefaultConnectionSettings(), peerSettings)
	stream, _ := mgr.OpenStream()
	payload := make([]byte, 16384) // 16KB payload
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		frames, _ := mgr.BuildDataFrames(stream.ID, payload, true)
		// Reset window for next iteration
		stream.SendWindow = int32(mgr.PeerSettings.InitialWindowSize)
		stream.State = StreamOpen
		for _, f := range frames {
			f.Payload = nil
		}
	}
}

// Benchmark applying received frames
func BenchmarkStreamManagerApplyReceivedFrame(b *testing.B) {
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	dataFrame := Frame{
		Header:  FrameHeader{Length: 4096, Type: FrameData, StreamID: 1},
		Payload: make([]byte, 4096),
	}
	// Create stream
	stream, _ := mgr.OpenStream()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = mgr.ApplyReceivedFrame(dataFrame)
		// Reset for next iteration
		stream.RecvWindow = int32(mgr.LocalSettings.InitialWindowSize)
	}
}

// Benchmark settings encoding
func BenchmarkEncodeSettingsPayload(b *testing.B) {
	settings := DefaultConnectionSettings()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = EncodeSettingsPayload(settings, nil)
	}
}

// Benchmark settings decoding
func BenchmarkApplySettingsPayload(b *testing.B) {
	settings := DefaultConnectionSettings()
	payload := EncodeSettingsPayload(settings, nil)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := DefaultConnectionSettings()
		_ = ApplySettingsPayload(&s, payload)
	}
}

// Benchmark window update processing
func BenchmarkWindowUpdateFrame(b *testing.B) {
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	stream, _ := mgr.OpenStream()
	windowFrame := Frame{
		Header:  FrameHeader{Length: 4, Type: FrameWindowUpdate, StreamID: stream.ID},
		Payload: []byte{0x00, 0x00, 0x10, 0x00}, // +4096
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = mgr.ApplyReceivedFrame(windowFrame)
		// Reset window
		stream.SendWindow = int32(mgr.PeerSettings.InitialWindowSize)
	}
}

// Benchmark multiple concurrent streams
func BenchmarkStreamManagerMultipleStreams(b *testing.B) {
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Open and close streams
		for j := 0; j < 100; j++ {
			s, _ := mgr.OpenStream()
			s.State = StreamClosed
			delete(mgr.Streams, s.ID)
		}
	}
}
