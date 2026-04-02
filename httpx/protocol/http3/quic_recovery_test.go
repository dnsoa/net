package http3

import (
	"sort"
	"testing"
	"time"
)

func TestServerConnLossRecoveryTracksAckedPackets(t *testing.T) {
	conn := NewServerConn(NewServerSession(), NewMemoryStreamOpenerFactory().NewStreamOpener())
	base := time.Unix(100, 0)
	if err := conn.RecordSentPacket(QUICPacketNumberSpaceApplication, QUICSentPacket{
		PacketNumber: 1,
		SentAt:       base,
		AckEliciting: true,
		Frames: []QUICSentFrame{{
			FrameType: quicStreamFrameTypeBase,
			StreamID:  0,
			Offset:    0,
			Payload:   []byte("hello"),
		}},
	}); err != nil {
		t.Fatalf("record sent packet: %v", err)
	}
	if err := conn.handleAckFrameAt(QUICPacketNumberSpaceApplication, QUICAckFrame{
		LargestAcknowledged: 1,
		Ranges:              []QUICAckRange{{Smallest: 1, Largest: 1}},
	}, base.Add(50*time.Millisecond)); err != nil {
		t.Fatalf("handle ack frame: %v", err)
	}

	recovery := conn.Snapshot().ApplicationPacketSpace.LossRecovery
	if recovery.OutstandingPackets != 0 {
		t.Fatalf("expected no outstanding packets, got %+v", recovery)
	}
	if recovery.AckedPackets != 1 {
		t.Fatalf("expected 1 acked packet, got %+v", recovery)
	}
	if recovery.AckElicitingInFlight != 0 || recovery.BytesInFlight != 0 {
		t.Fatalf("expected in-flight counters to clear, got %+v", recovery)
	}
	if recovery.LatestRTT != 50*time.Millisecond || recovery.SmoothedRTT != 50*time.Millisecond {
		t.Fatalf("unexpected rtt snapshot %+v", recovery)
	}
	if recovery.PTOArmed {
		t.Fatalf("expected PTO to disarm after ack, got %+v", recovery)
	}
	if pending, err := conn.DrainPendingRetransmissions(QUICPacketNumberSpaceApplication); err != nil {
		t.Fatalf("drain retransmissions: %v", err)
	} else if len(pending) != 0 {
		t.Fatalf("expected no pending retransmissions, got %+v", pending)
	}
}

func TestServerConnLossRecoveryDetectsPacketThresholdLoss(t *testing.T) {
	conn := NewServerConn(NewServerSession(), NewMemoryStreamOpenerFactory().NewStreamOpener())
	base := time.Unix(200, 0)
	for packetNumber := uint64(1); packetNumber <= 4; packetNumber++ {
		if err := conn.RecordSentPacket(QUICPacketNumberSpaceApplication, QUICSentPacket{
			PacketNumber: packetNumber,
			SentAt:       base.Add(time.Duration(packetNumber) * 10 * time.Millisecond),
			AckEliciting: true,
			Frames: []QUICSentFrame{{
				FrameType: quicStreamFrameTypeBase,
				StreamID:  0,
				Offset:    packetNumber - 1,
				Payload:   []byte{byte('a' + packetNumber - 1)},
			}},
		}); err != nil {
			t.Fatalf("record sent packet %d: %v", packetNumber, err)
		}
	}
	if err := conn.handleAckFrameAt(QUICPacketNumberSpaceApplication, QUICAckFrame{
		LargestAcknowledged: 4,
		Ranges:              []QUICAckRange{{Smallest: 4, Largest: 4}},
	}, base.Add(120*time.Millisecond)); err != nil {
		t.Fatalf("handle ack frame: %v", err)
	}

	pending, err := conn.DrainPendingRetransmissions(QUICPacketNumberSpaceApplication)
	if err != nil {
		t.Fatalf("drain retransmissions: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected one lost packet queued for retransmission, got %+v", pending)
	}
	if pending[0].OriginalPacketNumber != 1 || pending[0].Probe {
		t.Fatalf("unexpected retransmission %+v", pending[0])
	}
	if string(pending[0].Frames[0].Payload) != "a" {
		t.Fatalf("unexpected retransmission payload %+v", pending[0].Frames)
	}
	recovery := conn.Snapshot().ApplicationPacketSpace.LossRecovery
	if recovery.LostPackets != 1 {
		t.Fatalf("expected one lost packet, got %+v", recovery)
	}
	if recovery.OutstandingPackets != 2 {
		t.Fatalf("expected two outstanding packets after ack/loss, got %+v", recovery)
	}
}

func TestServerConnLossRecoveryDetectsTimeThresholdLoss(t *testing.T) {
	conn := NewServerConn(NewServerSession(), NewMemoryStreamOpenerFactory().NewStreamOpener())
	base := time.Unix(300, 0)
	for packetNumber := uint64(10); packetNumber <= 12; packetNumber++ {
		if err := conn.RecordSentPacket(QUICPacketNumberSpaceApplication, QUICSentPacket{
			PacketNumber: packetNumber,
			SentAt:       base.Add(time.Duration(packetNumber-10) * 10 * time.Millisecond),
			AckEliciting: true,
			Frames: []QUICSentFrame{{
				FrameType: quicStreamFrameTypeBase,
				StreamID:  0,
				Offset:    packetNumber - 10,
				Payload:   []byte{byte(packetNumber)},
			}},
		}); err != nil {
			t.Fatalf("record sent packet %d: %v", packetNumber, err)
		}
	}
	if err := conn.handleAckFrameAt(QUICPacketNumberSpaceApplication, QUICAckFrame{
		LargestAcknowledged: 12,
		Ranges:              []QUICAckRange{{Smallest: 12, Largest: 12}},
	}, base.Add(100*time.Millisecond)); err != nil {
		t.Fatalf("handle ack frame: %v", err)
	}
	if err := conn.AdvanceLossRecovery(base.Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("advance loss recovery: %v", err)
	}

	pending, err := conn.DrainPendingRetransmissions(QUICPacketNumberSpaceApplication)
	if err != nil {
		t.Fatalf("drain retransmissions: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected two time-threshold retransmissions, got %+v", pending)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].OriginalPacketNumber < pending[j].OriginalPacketNumber })
	if pending[0].OriginalPacketNumber != 10 || pending[1].OriginalPacketNumber != 11 {
		t.Fatalf("unexpected retransmissions %+v", pending)
	}
	recovery := conn.Snapshot().ApplicationPacketSpace.LossRecovery
	if recovery.LostPackets != 2 {
		t.Fatalf("expected two lost packets, got %+v", recovery)
	}
	if recovery.OutstandingPackets != 0 {
		t.Fatalf("expected no outstanding packets after loss detection, got %+v", recovery)
	}
}

func TestServerConnLossRecoveryQueuesProbeTimeout(t *testing.T) {
	conn := NewServerConn(NewServerSession(), NewMemoryStreamOpenerFactory().NewStreamOpener())
	base := time.Unix(400, 0)
	if err := conn.RecordSentPacket(QUICPacketNumberSpaceApplication, QUICSentPacket{
		PacketNumber: 7,
		SentAt:       base,
		AckEliciting: true,
		Frames: []QUICSentFrame{{
			FrameType: quicStreamFrameTypeBase,
			StreamID:  0,
			Offset:    0,
			Payload:   []byte("probe"),
		}},
	}); err != nil {
		t.Fatalf("record sent packet: %v", err)
	}
	if err := conn.AdvanceLossRecovery(base.Add(700 * time.Millisecond)); err != nil {
		t.Fatalf("advance loss recovery: %v", err)
	}
	pending, err := conn.DrainPendingRetransmissions(QUICPacketNumberSpaceApplication)
	if err != nil {
		t.Fatalf("drain retransmissions: %v", err)
	}
	if len(pending) != 1 || !pending[0].Probe || pending[0].OriginalPacketNumber != 7 {
		t.Fatalf("unexpected PTO retransmission %+v", pending)
	}
	if err := conn.AdvanceLossRecovery(base.Add(800 * time.Millisecond)); err != nil {
		t.Fatalf("advance loss recovery second time: %v", err)
	}
	pending, err = conn.DrainPendingRetransmissions(QUICPacketNumberSpaceApplication)
	if err != nil {
		t.Fatalf("drain retransmissions second time: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected PTO queue to avoid duplicates, got %+v", pending)
	}
	recovery := conn.Snapshot().ApplicationPacketSpace.LossRecovery
	if recovery.ProbeTimeouts != 1 {
		t.Fatalf("expected one PTO event, got %+v", recovery)
	}
	if !recovery.PTOArmed {
		t.Fatalf("expected PTO to stay armed while packet remains outstanding, got %+v", recovery)
	}
}
