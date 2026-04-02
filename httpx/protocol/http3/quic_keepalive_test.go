package http3

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestServerConnArmsAndDrainsKeepAlivePing(t *testing.T) {
	conn := NewServerConn(NewServerSession(), NewMemoryStreamOpenerFactory().NewStreamOpener())
	base := time.Unix(1000, 0)
	if conn.armKeepAliveAt(base, 5*time.Second) {
		t.Fatal("expected first keepalive arm to initialize activity only")
	}
	if conn.armKeepAliveAt(base.Add(4*time.Second), 5*time.Second) {
		t.Fatal("expected keepalive to stay idle below interval")
	}
	if !conn.armKeepAliveAt(base.Add(5*time.Second), 5*time.Second) {
		t.Fatal("expected keepalive ping to arm after interval")
	}
	snapshot := conn.KeepAliveSnapshot()
	if !snapshot.PendingPing {
		t.Fatal("expected pending ping after arm")
	}
	frame, err := conn.drainPendingPingFrameAt(base.Add(5 * time.Second))
	if err != nil {
		t.Fatalf("drain ping frame: %v", err)
	}
	if !bytes.Equal(frame, []byte{quicFrameTypePing}) {
		t.Fatalf("unexpected ping frame %x", frame)
	}
	snapshot = conn.KeepAliveSnapshot()
	if snapshot.PendingPing {
		t.Fatal("expected pending ping to clear after drain")
	}
	if snapshot.PingFramesSent != 1 {
		t.Fatalf("expected one sent ping, got %+v", snapshot)
	}
	if conn.isIdleAt(base.Add(9*time.Second), 5*time.Second) {
		t.Fatal("expected outbound ping to refresh activity")
	}
	if !conn.isIdleAt(base.Add(11*time.Second), 5*time.Second) {
		t.Fatal("expected idle timeout after last activity passes threshold")
	}
}

func TestServerConnTracksReceivedPingFrame(t *testing.T) {
	conn := NewServerConn(NewServerSession(), NewMemoryStreamOpenerFactory().NewStreamOpener())
	dcid := bytes.Repeat([]byte{0x55}, DefaultShortHeaderDestinationConnectionIDLength)
	if _, err := conn.HandlePacket(context.Background(), buildTestQUIC1RTTPacket(dcid, []byte{quicFrameTypePing}), nil); err != nil {
		t.Fatalf("handle ping packet: %v", err)
	}
	snapshot := conn.KeepAliveSnapshot()
	if snapshot.PingFramesSeen != 1 {
		t.Fatalf("expected one received ping, got %+v", snapshot)
	}
	if snapshot.LastActivityAt.IsZero() || snapshot.LastReceiveAt.IsZero() {
		t.Fatalf("expected activity timestamps after ping, got %+v", snapshot)
	}
}
