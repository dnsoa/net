package http2

import (
	"bytes"
	"testing"

	"github.com/dnsoa/net/httpx/core"
)

func TestFrameHeaderSerializeParse(t *testing.T) {
	h := FrameHeader{Length: 256, Type: FrameData, Flags: 0x01, StreamID: 1}
	serialized := h.Serialize()
	parsed := ParseFrameHeader(serialized)
	if parsed.Length != h.Length || parsed.Type != h.Type || parsed.Flags != h.Flags || parsed.StreamID != h.StreamID {
		t.Fatalf("unexpected parsed frame header: %+v", parsed)
	}
}

func TestSettingsPayloadRoundTrip(t *testing.T) {
	in := ConnectionSettings{HeaderTableSize: 4096, EnablePush: false, MaxConcurrentStreams: 123, InitialWindowSize: 65535, MaxFrameSize: 16384, MaxHeaderListSize: 9000}
	payload := EncodeSettingsPayload(in, nil)
	var out ConnectionSettings
	if err := ApplySettingsPayload(&out, payload); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	if out != in {
		t.Fatalf("settings mismatch: got %+v want %+v", out, in)
	}
}

func TestConnHandshakeAndFrameIO(t *testing.T) {
	var wire bytes.Buffer
	conn := NewConn(nil, &wire)
	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if !bytes.HasPrefix(wire.Bytes(), []byte(Preface)) {
		t.Fatalf("missing http2 preface: %q", wire.Bytes())
	}
	payload := []byte("abc")
	header := FrameHeader{Length: uint32(len(payload)), Type: FramePing, StreamID: 0}
	if err := conn.WriteFrame(header, payload); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	reader := bytes.NewReader(wire.Bytes()[len(Preface):])
	readConn := NewConn(reader, nil)
	frame, err := readConn.ReadFrame(1024)
	if err != nil {
		t.Fatalf("read settings frame: %v", err)
	}
	if frame.Header.Type != FrameSettings {
		t.Fatalf("unexpected first frame type: %v", frame.Header.Type)
	}
	frame, err = readConn.ReadFrame(1024)
	if err != nil {
		t.Fatalf("read ping frame: %v", err)
	}
	if frame.Header.Type != FramePing || string(frame.Payload) != "abc" {
		t.Fatalf("unexpected second frame: %+v payload=%q", frame.Header, frame.Payload)
	}
}

func TestNegotiateVersionAndH2C(t *testing.T) {
	if NegotiateVersion([]byte(ALPNHTTP2)) != NegotiatedHTTP2 {
		t.Fatal("expected http2 negotiation")
	}
	if NegotiateVersion([]byte(ALPNHTTP3)).ToVersion() != core.VersionHTTP3 {
		t.Fatal("expected http3 version")
	}
	headers := core.NewHeaders()
	defer headers.Reset()
	headers.Set([]byte("Upgrade"), []byte("h2c"))
	headers.Set([]byte("Connection"), []byte("Upgrade, HTTP2-Settings"))
	headers.Set([]byte("HTTP2-Settings"), []byte("AAMAAABkAAQCAAAAAAIAAAAA"))
	if !IsH2CUpgradeRequest(&headers) {
		t.Fatal("expected valid h2c upgrade request")
	}
}
