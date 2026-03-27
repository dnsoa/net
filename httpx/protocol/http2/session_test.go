package http2

import (
	"bytes"
	"testing"

	"github.com/dnsoa/net/httpx/core"
)

func TestSessionRequestResponseRoundTrip(t *testing.T) {
	var clientToServer bytes.Buffer
	var serverToClient bytes.Buffer

	client := NewClientSession(&serverToClient, &clientToServer)
	server := NewServerSession(&clientToServer, &serverToClient)

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	if err := req.Init(core.MethodPost, "https://example.com/api/items?id=7"); err != nil {
		t.Fatalf("init request: %v", err)
	}
	req.Headers.SetString("content-type", "application/json")
	req.Body = append(req.Body, []byte(`{"name":"httpx"}`)...)

	streamID, err := client.WriteRequest(req)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}
	if streamID != 1 {
		t.Fatalf("unexpected stream id %d", streamID)
	}

	gotStreamID, gotReq, err := server.ReadRequest()
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	defer core.ReleaseRequest(gotReq)
	if gotStreamID != streamID {
		t.Fatalf("unexpected request stream id %d", gotStreamID)
	}
	if gotReq.Method != core.MethodPost {
		t.Fatalf("unexpected method %v", gotReq.Method)
	}
	if string(gotReq.URI.Path) != "/api/items" || string(gotReq.URI.Query) != "id=7" {
		t.Fatalf("unexpected uri path=%q query=%q", gotReq.URI.Path, gotReq.URI.Query)
	}
	if string(gotReq.Body) != `{"name":"httpx"}` {
		t.Fatalf("unexpected request body %q", gotReq.Body)
	}

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP2
	resp.Status = core.NewStatus(200)
	resp.Headers.SetString("content-type", "application/json")
	resp.Body = append(resp.Body, []byte(`{"ok":true}`)...)

	if err := server.WriteResponse(gotStreamID, resp); err != nil {
		t.Fatalf("write response: %v", err)
	}

	respStreamID, gotResp, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer core.ReleaseResponse(gotResp)
	if respStreamID != streamID {
		t.Fatalf("unexpected response stream id %d", respStreamID)
	}
	if gotResp.Status.Code != 200 {
		t.Fatalf("unexpected response status %d", gotResp.Status.Code)
	}
	if string(gotResp.Body) != `{"ok":true}` {
		t.Fatalf("unexpected response body %q", gotResp.Body)
	}
	if got := gotResp.Headers.Get("content-type"); string(got) != "application/json" {
		t.Fatalf("unexpected content-type %q", got)
	}
}

func TestSessionReadRequestHeaderOnly(t *testing.T) {
	var wire bytes.Buffer
	client := NewClientSession(nil, &wire)
	server := NewServerSession(&wire, nil)

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	if err := req.Init(core.MethodGet, "https://example.com/ping"); err != nil {
		t.Fatalf("init request: %v", err)
	}

	if _, err := client.WriteRequest(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_, gotReq, err := server.ReadRequest()
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	defer core.ReleaseRequest(gotReq)
	if string(gotReq.Body) != "" {
		t.Fatalf("expected empty body, got %q", gotReq.Body)
	}
	if gotReq.Method != core.MethodGet {
		t.Fatalf("unexpected method %v", gotReq.Method)
	}
}

func TestSessionRequestResponseTrailersAndSettingsAck(t *testing.T) {
	var clientToServer bytes.Buffer
	var serverToClient bytes.Buffer

	client := NewClientSession(&serverToClient, &clientToServer)
	server := NewServerSession(&clientToServer, &serverToClient)

	settingsPayload := EncodeSettingsPayload(ConnectionSettings{HeaderTableSize: 2048, EnablePush: false, MaxConcurrentStreams: 32, InitialWindowSize: 65535, MaxFrameSize: 8192, MaxHeaderListSize: 4096}, nil)
	if err := client.conn.WriteFrame(FrameHeader{Length: uint32(len(settingsPayload)), Type: FrameSettings, StreamID: 0}, settingsPayload); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	if err := req.Init(core.MethodPost, "https://example.com/upload"); err != nil {
		t.Fatalf("init request: %v", err)
	}
	req.Body = append(req.Body, []byte("payload")...)
	req.Trailers.SetString("x-digest", "abc")

	streamID, err := client.WriteRequest(req)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	gotStreamID, gotReq, err := server.ReadRequest()
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	defer core.ReleaseRequest(gotReq)
	if gotStreamID != streamID {
		t.Fatalf("unexpected request stream id %d", gotStreamID)
	}
	if string(gotReq.Trailers.Get("x-digest")) != "abc" {
		t.Fatalf("unexpected request trailer %q", gotReq.Trailers.Get("x-digest"))
	}

	ack, err := client.conn.ReadFrame(1024)
	if err != nil {
		t.Fatalf("read settings ack: %v", err)
	}
	if ack.Header.Type != FrameSettings || ack.Header.Flags&FlagAck == 0 {
		t.Fatalf("unexpected settings ack frame %+v", ack.Header)
	}

	resp := core.AcquireResponse()
	defer core.ReleaseResponse(resp)
	resp.Version = core.VersionHTTP2
	resp.Status = core.NewStatus(200)
	resp.Body = append(resp.Body, []byte("ok")...)
	resp.Trailers.SetString("x-cache", "hit")

	if err := server.WriteResponse(streamID, resp); err != nil {
		t.Fatalf("write response: %v", err)
	}

	respStreamID, gotResp, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer core.ReleaseResponse(gotResp)
	if respStreamID != streamID {
		t.Fatalf("unexpected response stream id %d", respStreamID)
	}
	if string(gotResp.Trailers.Get("x-cache")) != "hit" {
		t.Fatalf("unexpected response trailer %q", gotResp.Trailers.Get("x-cache"))
	}
	if server.streams.PeerSettings.MaxFrameSize != 8192 {
		t.Fatalf("expected server peer settings update, got %d", server.streams.PeerSettings.MaxFrameSize)
	}
}
