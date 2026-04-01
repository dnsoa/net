package http2

import (
	"bytes"
	"testing"
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
