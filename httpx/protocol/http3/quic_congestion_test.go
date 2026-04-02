package http3

import (
	"testing"
	"time"
)

func TestServerConnCongestionWindowGrowsOnAck(t *testing.T) {
	conn := NewServerConn(NewServerSession(), NewMemoryStreamOpenerFactory().NewStreamOpener())
	base := time.Unix(500, 0)
	if got := conn.CongestionSnapshot().CongestionWindow; got != quicInitialCongestionWindow {
		t.Fatalf("unexpected initial congestion window %d", got)
	}
	if err := conn.RecordSentPacket(QUICPacketNumberSpaceApplication, QUICSentPacket{
		PacketNumber: 1,
		SentAt:       base,
		AckEliciting: true,
		Frames: []QUICSentFrame{{
			FrameType: quicStreamFrameTypeBase,
			Payload:   make([]byte, quicDefaultMaxDatagramSize),
		}},
	}); err != nil {
		t.Fatalf("record sent packet: %v", err)
	}
	if !conn.CanSend(quicDefaultMaxDatagramSize) {
		t.Fatal("expected congestion window to allow another datagram")
	}
	if err := conn.handleAckFrameAt(QUICPacketNumberSpaceApplication, QUICAckFrame{
		LargestAcknowledged: 1,
		Ranges:              []QUICAckRange{{Smallest: 1, Largest: 1}},
	}, base.Add(40*time.Millisecond)); err != nil {
		t.Fatalf("handle ack frame: %v", err)
	}
	snapshot := conn.CongestionSnapshot()
	if snapshot.BytesInFlight != 0 {
		t.Fatalf("expected bytes in flight to clear, got %+v", snapshot)
	}
	if snapshot.CongestionWindow != quicInitialCongestionWindow+quicDefaultMaxDatagramSize {
		t.Fatalf("expected congestion window to grow in slow start, got %+v", snapshot)
	}
}

func TestServerConnCongestionWindowShrinksOnLoss(t *testing.T) {
	conn := NewServerConn(NewServerSession(), NewMemoryStreamOpenerFactory().NewStreamOpener())
	base := time.Unix(600, 0)
	for packetNumber := uint64(1); packetNumber <= 4; packetNumber++ {
		if err := conn.RecordSentPacket(QUICPacketNumberSpaceApplication, QUICSentPacket{
			PacketNumber: packetNumber,
			SentAt:       base.Add(time.Duration(packetNumber) * time.Millisecond),
			AckEliciting: true,
			Frames: []QUICSentFrame{{
				FrameType: quicStreamFrameTypeBase,
				Payload:   make([]byte, quicDefaultMaxDatagramSize),
			}},
		}); err != nil {
			t.Fatalf("record sent packet %d: %v", packetNumber, err)
		}
	}
	if err := conn.handleAckFrameAt(QUICPacketNumberSpaceApplication, QUICAckFrame{
		LargestAcknowledged: 4,
		Ranges:              []QUICAckRange{{Smallest: 4, Largest: 4}},
	}, base.Add(50*time.Millisecond)); err != nil {
		t.Fatalf("handle ack frame: %v", err)
	}
	snapshot := conn.CongestionSnapshot()
	if snapshot.CongestionEvents != 1 {
		t.Fatalf("expected one congestion event, got %+v", snapshot)
	}
	if snapshot.CongestionWindow != (quicInitialCongestionWindow+quicDefaultMaxDatagramSize)/2 {
		t.Fatalf("expected congestion window to halve after loss, got %+v", snapshot)
	}
	if snapshot.SlowStartThreshold != snapshot.CongestionWindow {
		t.Fatalf("expected ssthresh to match reduced cwnd, got %+v", snapshot)
	}
	if snapshot.BytesInFlight != 2*quicDefaultMaxDatagramSize {
		t.Fatalf("expected bytes in flight to reflect acked and lost packets, got %+v", snapshot)
	}
}
