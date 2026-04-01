package http2

import (
	"testing"

	"github.com/dnsoa/net/httpx/core"
)

func TestStreamManagerOpenStream(t *testing.T) {
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	stream, err := mgr.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if stream.ID != 1 {
		t.Fatalf("unexpected stream id %d", stream.ID)
	}
	if stream.State != StreamOpen {
		t.Fatalf("unexpected initial stream state %v", stream.State)
	}
}

func TestStreamManagerBuildDataFramesSplit(t *testing.T) {
	peer := DefaultConnectionSettings()
	peer.MaxFrameSize = 4
	mgr := NewStreamManager(true, DefaultConnectionSettings(), peer)
	stream, err := mgr.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	frames, err := mgr.BuildDataFrames(stream.ID, []byte("abcdefghij"), true)
	if err != nil {
		t.Fatalf("build data frames: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("unexpected frame count %d", len(frames))
	}
	if frames[2].Header.Flags&FlagEndStream == 0 {
		t.Fatal("expected final frame to carry end-stream flag")
	}
	if stream.State != StreamHalfClosedLocal {
		t.Fatalf("unexpected stream state after sending end-stream %v", stream.State)
	}
}

func TestStreamManagerApplyReceivedHeadersAndData(t *testing.T) {
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	headers := mgr.BuildHeadersFrame(2, []byte("header-block"), false, true)
	if err := mgr.ApplyReceivedFrame(headers); err != nil {
		t.Fatalf("apply received headers: %v", err)
	}
	stream, ok := mgr.Get(2)
	if !ok {
		t.Fatal("expected remote stream to be created")
	}
	if stream.State != StreamOpen {
		t.Fatalf("unexpected stream state %v", stream.State)
	}
	data := Frame{
		Header:  FrameHeader{Length: 3, Type: FrameData, Flags: FlagEndStream, StreamID: 2},
		Payload: []byte("abc"),
	}
	if err := mgr.ApplyReceivedFrame(data); err != nil {
		t.Fatalf("apply received data: %v", err)
	}
	stream, ok = mgr.Get(2)
	if !ok {
		t.Fatal("expected stream to remain tracked")
	}
	if stream.State != StreamHalfClosedRemote {
		t.Fatalf("unexpected stream state after remote end-stream %v", stream.State)
	}
}

func TestStreamManagerWindowUpdate(t *testing.T) {
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	stream, err := mgr.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	original := stream.SendWindow
	frame := Frame{
		Header:  FrameHeader{Length: 4, Type: FrameWindowUpdate, StreamID: stream.ID},
		Payload: []byte{0x00, 0x00, 0x01, 0x00},
	}
	if err := mgr.ApplyReceivedFrame(frame); err != nil {
		t.Fatalf("apply window update: %v", err)
	}
	if stream.SendWindow != original+256 {
		t.Fatalf("unexpected send window %d", stream.SendWindow)
	}
}

func TestStreamManagerCloseSequence(t *testing.T) {
	mgr := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	stream, err := mgr.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	headers := mgr.BuildHeadersFrame(stream.ID, []byte("headers"), false, true)
	if err := mgr.ApplySentFrame(headers); err != nil {
		t.Fatalf("apply sent headers: %v", err)
	}
	data := Frame{
		Header:  FrameHeader{Length: 2, Type: FrameData, Flags: FlagEndStream, StreamID: stream.ID},
		Payload: []byte("ok"),
	}
	if err := mgr.ApplySentFrame(data); err != nil {
		t.Fatalf("apply sent data: %v", err)
	}
	stream, ok := mgr.Get(stream.ID)
	if !ok || stream.State != StreamHalfClosedLocal {
		t.Fatalf("unexpected state after local close: ok=%v state=%v", ok, stream.State)
	}
	remoteEnd := Frame{
		Header: FrameHeader{Length: 0, Type: FrameHeaders, Flags: FlagEndStream | FlagEndHeaders, StreamID: stream.ID},
	}
	if err := mgr.ApplyReceivedFrame(remoteEnd); err != nil {
		t.Fatalf("apply remote end headers: %v", err)
	}
	if _, ok := mgr.Get(stream.ID); ok {
		t.Fatal("expected closed stream to be removed")
	}
}

func TestBuildRequestHeaderFramesAndDecode(t *testing.T) {
	peer := DefaultConnectionSettings()
	peer.MaxFrameSize = 8
	sender := NewStreamManager(true, DefaultConnectionSettings(), peer)
	stream, err := sender.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodPost, "https://example.com/upload?part=1")
	req.Headers.SetString("content-type", "application/json")
	req.Headers.SetString("x-trace-id", "abc123")

	frames, err := sender.BuildRequestHeaderFrames(stream.ID, req, false)
	if err != nil {
		t.Fatalf("build request headers: %v", err)
	}
	if len(frames) < 2 {
		t.Fatalf("expected continuation frames, got %d", len(frames))
	}
	if frames[0].Header.Type != FrameHeaders {
		t.Fatalf("unexpected first frame type %v", frames[0].Header.Type)
	}
	if frames[len(frames)-1].Header.Type != FrameContinuation || frames[len(frames)-1].Header.Flags&FlagEndHeaders == 0 {
		t.Fatalf("expected final continuation with END_HEADERS, got %+v", frames[len(frames)-1].Header)
	}

	receiver := NewStreamManager(false, DefaultConnectionSettings(), DefaultConnectionSettings())
	var decoded *DecodedHeaderBlock
	for _, frame := range frames {
		decoded, err = receiver.ReceiveHeaderBlockFrame(frame)
		if err != nil {
			t.Fatalf("receive header block frame: %v", err)
		}
	}
	if decoded == nil {
		t.Fatal("expected decoded header block")
	}
	decodedReq, err := receiver.DecodeRequestHeaderBlock(decoded.Fields)
	if err != nil {
		t.Fatalf("decode request header block: %v", err)
	}
	defer core.ReleaseRequest(decodedReq)
	if decodedReq.Method != core.MethodPost {
		t.Fatalf("unexpected method %v", decodedReq.Method)
	}
	if string(decodedReq.URI.Path) != "/upload" || string(decodedReq.URI.Query) != "part=1" {
		t.Fatalf("unexpected decoded uri path=%q query=%q", decodedReq.URI.Path, decodedReq.URI.Query)
	}
	if got := decodedReq.Headers.Get("x-trace-id"); string(got) != "abc123" {
		t.Fatalf("unexpected x-trace-id header %q", got)
	}
	if got := decodedReq.Headers.Get("Host"); string(got) != "example.com" {
		t.Fatalf("unexpected host header %q", got)
	}
}

func TestBuildResponseHeaderFramesAndDecode(t *testing.T) {
	peer := DefaultConnectionSettings()
	peer.MaxFrameSize = 10
	sender := NewStreamManager(false, DefaultConnectionSettings(), peer)
	sender.Streams[1] = &Stream{ID: 1, State: StreamOpen, SendWindow: 65535, RecvWindow: 65535}
	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP2
	resp.Status = core.NewStatus(204)
	resp.Headers.SetString("x-served-by", "edge-a")

	frames, err := sender.BuildResponseHeaderFrames(1, resp, true)
	if err != nil {
		t.Fatalf("build response headers: %v", err)
	}
	receiver := NewStreamManager(true, DefaultConnectionSettings(), DefaultConnectionSettings())
	receiver.Streams[1] = &Stream{ID: 1, State: StreamHalfClosedLocal, SendWindow: 65535, RecvWindow: 65535}
	var decoded *DecodedHeaderBlock
	for _, frame := range frames {
		decoded, err = receiver.ReceiveHeaderBlockFrame(frame)
		if err != nil {
			t.Fatalf("receive response header block: %v", err)
		}
	}
	if decoded == nil || !decoded.EndStream {
		t.Fatal("expected decoded end-stream response block")
	}
	decodedResp, err := receiver.DecodeResponseHeaderBlock(decoded.Fields)
	if err != nil {
		t.Fatalf("decode response header block: %v", err)
	}
	defer core.ReleaseResponse(decodedResp)
	if decodedResp.Status.Code != 204 {
		t.Fatalf("unexpected status %d", decodedResp.Status.Code)
	}
	if got := decodedResp.Headers.Get("x-served-by"); string(got) != "edge-a" {
		t.Fatalf("unexpected x-served-by header %q", got)
	}
	if _, ok := receiver.Get(1); ok {
		t.Fatal("expected stream to close after remote end-stream headers")
	}
}

func TestReceiveHeaderBlockFrameRejectsInterleaving(t *testing.T) {
	mgr := NewStreamManager(false, DefaultConnectionSettings(), DefaultConnectionSettings())
	first := Frame{Header: FrameHeader{Length: 2, Type: FrameHeaders, StreamID: 1}, Payload: []byte{0x82, 0x84}}
	if _, err := mgr.ReceiveHeaderBlockFrame(first); err != nil {
		t.Fatalf("receive initial headers: %v", err)
	}
	second := Frame{Header: FrameHeader{Length: 1, Type: FrameHeaders, StreamID: 3}, Payload: []byte{0x84}}
	if _, err := mgr.ReceiveHeaderBlockFrame(second); err == nil {
		t.Fatal("expected interleaved header block to fail")
	}
	wrongCont := Frame{Header: FrameHeader{Length: 1, Type: FrameContinuation, StreamID: 3}, Payload: []byte{0x84}}
	if _, err := mgr.ReceiveHeaderBlockFrame(wrongCont); err == nil {
		t.Fatal("expected continuation stream mismatch to fail")
	}
}

func TestDecodeMultipleHeaderBlocksWithDynamicTableSizeUpdate(t *testing.T) {
	peer := DefaultConnectionSettings()
	sender := NewStreamManager(true, DefaultConnectionSettings(), peer)
	receiver := NewStreamManager(false, DefaultConnectionSettings(), DefaultConnectionSettings())

	stream1, err := sender.OpenStream()
	if err != nil {
		t.Fatalf("open stream1: %v", err)
	}
	req1 := core.AcquireRequest()
	defer core.ReleaseRequest(req1)
	initRequest(req1, core.MethodGet, "https://example.com/one")
	req1.Headers.SetString("x-trace-id", "one")
	frames1, err := sender.BuildRequestHeaderFrames(stream1.ID, req1, true)
	if err != nil {
		t.Fatalf("build request1 headers: %v", err)
	}
	var decoded1 *DecodedHeaderBlock
	for _, frame := range frames1 {
		decoded1, err = receiver.ReceiveHeaderBlockFrame(frame)
		if err != nil {
			t.Fatalf("receive request1 header block: %v", err)
		}
	}
	if decoded1 == nil {
		t.Fatal("expected decoded first header block")
	}

	// Force a dynamic table size update at the beginning of the next header block.
	sender.encoder.SetMaxDynamicTableSize(0)

	stream2, err := sender.OpenStream()
	if err != nil {
		t.Fatalf("open stream2: %v", err)
	}
	req2 := core.AcquireRequest()
	defer core.ReleaseRequest(req2)
	initRequest(req2, core.MethodGet, "https://example.com/two")
	req2.Headers.SetString("x-trace-id", "two")
	frames2, err := sender.BuildRequestHeaderFrames(stream2.ID, req2, true)
	if err != nil {
		t.Fatalf("build request2 headers: %v", err)
	}
	var decoded2 *DecodedHeaderBlock
	for _, frame := range frames2 {
		decoded2, err = receiver.ReceiveHeaderBlockFrame(frame)
		if err != nil {
			t.Fatalf("receive request2 header block: %v", err)
		}
	}
	if decoded2 == nil {
		t.Fatal("expected decoded second header block")
	}
	decodedReq2, err := receiver.DecodeRequestHeaderBlock(decoded2.Fields)
	if err != nil {
		t.Fatalf("decode request2 header block: %v", err)
	}
	defer core.ReleaseRequest(decodedReq2)
	if got := decodedReq2.Headers.Get("x-trace-id"); string(got) != "two" {
		t.Fatalf("unexpected x-trace-id header %q", got)
	}
	if string(decodedReq2.URI.Path) != "/two" {
		t.Fatalf("unexpected path %q", decodedReq2.URI.Path)
	}
}
