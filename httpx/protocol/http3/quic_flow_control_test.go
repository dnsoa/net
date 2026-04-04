package http3

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/dnsoa/net/httpx/core"
)

func TestServerConnRejectsStreamDataBeyondReceiveWindow(t *testing.T) {
	server := NewServerSession()
	server.settingsSent = true
	server.settingsReceived = true
	conn := NewServerConn(server, NewMemoryStreamOpenerFactory().NewStreamOpener())
	conn.state.PeerSettingsReady = true

	frame, err := buildQUICStreamFrame(0, 0, bytes.Repeat([]byte("a"), quicInitialStreamReceiveWindow+1), false)
	if err != nil {
		t.Fatalf("build stream frame: %v", err)
	}
	dcid := bytes.Repeat([]byte{0x33}, DefaultShortHeaderDestinationConnectionIDLength)
	_, err = conn.HandlePacket(context.Background(), buildTestQUIC1RTTPacket(dcid, frame), nil)
	if err == nil {
		t.Fatal("expected flow control error")
	}
	if !strings.Contains(err.Error(), "flow control exceeded") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServerConnDrainsPendingFlowControlFramesAfterConsumption(t *testing.T) {
	client := NewClientSession()
	client.settingsSent = true

	server := NewServerSession()
	server.settingsSent = true
	server.settingsReceived = true

	streams := &cancelTrackingPacketAssembler{}
	conn := NewServerConn(server, streams)
	conn.state.PeerSettingsReady = true

	req := core.AcquireRequest()
	defer core.ReleaseRequest(req)
	initRequest(req, core.MethodPost, "https://cdn.example.com/upload")
	body := []byte("payload")
	req.Headers.Set(core.HeaderContentLength, []byte("7"))
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	var encoded bytes.Buffer
	if err := client.WriteRequest(&encoded, req); err != nil {
		t.Fatalf("encode request: %v", err)
	}

	handler := ServerRequestHandlerFunc(func(ctx context.Context, got *core.Request) (*core.Response, error) {
		_, err := io.ReadAll(got.Body)
		if err != nil {
			return nil, err
		}
		resp := core.AcquireResponse()
		resp.Status = core.NewStatus(204)
		return resp, nil
	})

	if err := conn.observeReceivedStreamFrame(applicationPacket{StreamID: 0, IsStreamFrame: true, Payload: encoded.Bytes(), Fin: true}); err != nil {
		t.Fatalf("observe request stream data: %v", err)
	}
	if err := conn.handleRequestStream(context.Background(), applicationPacket{StreamID: 0, IsStreamFrame: true, Payload: encoded.Bytes(), Fin: true}, handler); err != nil {
		t.Fatalf("handle request stream: %v", err)
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	for !conn.RequestStreamComplete(0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !conn.RequestStreamComplete(0) {
		t.Fatal("expected request stream to complete")
	}

	frames, err := conn.DrainPendingFlowControlFrames()
	if err != nil {
		t.Fatalf("drain flow control frames: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("expected pending flow control frames")
	}

	seenConn := false
	for offset := 0; offset < len(frames); {
		switch frames[offset] {
		case quicFrameTypeMaxData:
			frame, consumed, err := ParseQUICMaxDataFrame(frames[offset:])
			if err != nil {
				t.Fatalf("parse max_data frame: %v", err)
			}
			if frame.MaximumData <= quicInitialConnectionReceiveWindow {
				t.Fatalf("expected max_data to grow, got %d", frame.MaximumData)
			}
			seenConn = true
			offset += consumed
		case quicFrameTypeMaxStreamData:
			frame, consumed, err := ParseQUICMaxStreamDataFrame(frames[offset:])
			if err != nil {
				t.Fatalf("parse max_stream_data frame: %v", err)
			}
			if frame.StreamID != 0 {
				t.Fatalf("unexpected stream id %d", frame.StreamID)
			}
			if frame.MaximumStreamData <= quicInitialStreamReceiveWindow {
				t.Fatalf("expected max_stream_data to grow, got %d", frame.MaximumStreamData)
			}
			offset += consumed
		default:
			t.Fatalf("unexpected frame type 0x%x", frames[offset])
		}
	}
	if !seenConn {
		t.Fatalf("expected max_data frame, seenConn=%v", seenConn)
	}
	// MAX_STREAM_DATA is not expected for a FIN-closed stream since
	// consumeAllStream clears the stream-level pending flag.
}

func TestServerConnAppliesPeerMaxDataAndMaxStreamData(t *testing.T) {
	conn := NewServerConn(NewServerSession(), NewMemoryStreamOpenerFactory().NewStreamOpener())
	conn.state.flowControl.peerMaxData = 1
	conn.state.flowControl.streams = map[uint64]*quicFlowControlStream{4: {peerMaxData: 1}}
	if conn.CanSendStreamData(4, 0, 2) {
		t.Fatal("expected stream send to be blocked before peer limits increase")
	}

	maxData, err := AppendQUICMaxDataFrame(nil, 32)
	if err != nil {
		t.Fatalf("append max_data: %v", err)
	}
	maxStreamData, err := AppendQUICMaxStreamDataFrame(nil, 4, 16)
	if err != nil {
		t.Fatalf("append max_stream_data: %v", err)
	}
	dcid := bytes.Repeat([]byte{0x44}, DefaultShortHeaderDestinationConnectionIDLength)
	if _, err := conn.HandlePacket(context.Background(), buildTestQUIC1RTTPacket(dcid, append(maxData, maxStreamData...)), nil); err != nil {
		t.Fatalf("handle peer flow control packet: %v", err)
	}
	if !conn.CanSendStreamData(4, 0, 16) {
		t.Fatal("expected stream send to be allowed after peer limits update")
	}
	if got := conn.AvailableStreamSendWindow(4); got != 16 {
		t.Fatalf("unexpected stream send window %d", got)
	}

	err = conn.RecordSentPacket(QUICPacketNumberSpaceApplication, QUICSentPacket{
		PacketNumber: 1,
		AckEliciting: true,
		Frames: []QUICSentFrame{{
			FrameType: quicStreamFrameTypeBase,
			StreamID:  4,
			Offset:    0,
			Payload:   bytes.Repeat([]byte("b"), 16),
		}},
	})
	if err != nil {
		t.Fatalf("record sent packet within peer limit: %v", err)
	}
	if conn.CanSendStreamData(4, 16, 1) {
		t.Fatal("expected send window to be exhausted")
	}
	err = conn.RecordSentPacket(QUICPacketNumberSpaceApplication, QUICSentPacket{
		PacketNumber: 2,
		AckEliciting: true,
		Frames: []QUICSentFrame{{
			FrameType: quicStreamFrameTypeBase,
			StreamID:  4,
			Offset:    16,
			Payload:   []byte("x"),
		}},
	})
	if err == nil {
		t.Fatal("expected peer flow control error")
	}
	if !strings.Contains(err.Error(), "peer stream flow control exceeded") {
		t.Fatalf("unexpected error: %v", err)
	}
}
