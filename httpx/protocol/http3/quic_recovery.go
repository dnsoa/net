package http3

import (
	"fmt"
	"sort"
	"time"
)

const (
	quicPacketLossThreshold = 3
	quicInitialRTT          = 333 * time.Millisecond
	quicTimerGranularity    = time.Millisecond
)

type QUICSentFrame struct {
	FrameType byte
	StreamID  uint64
	Offset    uint64
	Payload   []byte
	Fin       bool
}

type QUICSentPacket struct {
	PacketNumber uint64
	SentAt       time.Time
	AckEliciting bool
	Frames       []QUICSentFrame
}

type QUICPendingRetransmission struct {
	OriginalPacketNumber uint64
	Probe                bool
	Frames               []QUICSentFrame
}

type QUICLossRecoverySnapshot struct {
	OutstandingPackets    uint64
	AckElicitingInFlight  uint64
	BytesInFlight         uint64
	AckedPackets          uint64
	LostPackets           uint64
	RetransmissionsQueued uint64
	ProbeTimeouts         uint64
	LatestRTT             time.Duration
	SmoothedRTT           time.Duration
	RTTVariance           time.Duration
	PTOArmed              bool
	PTODeadline           time.Time
}

type quicLossRecoveryState struct {
	sentPackets           map[uint64]QUICSentPacket
	pendingRetransmission []QUICPendingRetransmission
	probeQueued           map[uint64]struct{}
	ackElicitingInFlight  uint64
	bytesInFlight         uint64
	ackedPackets          uint64
	lostPackets           uint64
	retransmissionsQueued uint64
	probeTimeouts         uint64
	latestRTT             time.Duration
	smoothedRTT           time.Duration
	rttVar                time.Duration
}

func (s *quicPacketNumberSpaceState) recordSentPacket(packet QUICSentPacket) error {
	if s == nil {
		return fmt.Errorf("http3 packet number space is nil")
	}
	return s.recovery.recordSentPacket(packet)
}

func (s *quicPacketNumberSpaceState) observeAckAt(frame QUICAckFrame, now time.Time) quicLossRecoveryEvents {
	if s == nil {
		return quicLossRecoveryEvents{}
	}
	s.observeAck(frame)
	return s.recovery.observeAck(frame, now)
}

func (s *quicPacketNumberSpaceState) advanceLossRecovery(now time.Time) quicLossRecoveryEvents {
	if s == nil {
		return quicLossRecoveryEvents{}
	}
	return s.recovery.advance(now, s.largestAcked, s.largestAckedSet)
}

func (s *quicPacketNumberSpaceState) drainPendingRetransmissions() []QUICPendingRetransmission {
	if s == nil {
		return nil
	}
	return s.recovery.drainPendingRetransmissions()
}

func (s *quicLossRecoveryState) recordSentPacket(packet QUICSentPacket) error {
	if packet.SentAt.IsZero() {
		packet.SentAt = time.Now()
	}
	if s.sentPackets == nil {
		s.sentPackets = make(map[uint64]QUICSentPacket)
	}
	if _, exists := s.sentPackets[packet.PacketNumber]; exists {
		return fmt.Errorf("http3 duplicate sent packet number %d", packet.PacketNumber)
	}
	packet.Frames = cloneQUICSentFrames(packet.Frames)
	s.sentPackets[packet.PacketNumber] = packet
	if packet.AckEliciting {
		s.ackElicitingInFlight++
		s.bytesInFlight += packet.payloadBytes()
	}
	delete(s.probeQueued, packet.PacketNumber)
	return nil
}

func (s *quicLossRecoveryState) observeAck(frame QUICAckFrame, now time.Time) quicLossRecoveryEvents {
	if s == nil || len(s.sentPackets) == 0 {
		return quicLossRecoveryEvents{}
	}
	events := quicLossRecoveryEvents{}
	var largestAckedPacket *QUICSentPacket
	ackedPacketNumbers := make([]uint64, 0, len(s.sentPackets))
	for packetNumber, packet := range s.sentPackets {
		if !ackFrameContainsPacket(frame, packetNumber) {
			continue
		}
		ackedPacketNumbers = append(ackedPacketNumbers, packetNumber)
		if largestAckedPacket == nil || packet.PacketNumber > largestAckedPacket.PacketNumber {
			packetCopy := packet
			largestAckedPacket = &packetCopy
		}
	}
	if largestAckedPacket != nil && !now.IsZero() && !largestAckedPacket.SentAt.IsZero() && !now.Before(largestAckedPacket.SentAt) {
		s.updateRTT(now.Sub(largestAckedPacket.SentAt))
		events.largestAckedSentAt = largestAckedPacket.SentAt
	}
	for _, packetNumber := range ackedPacketNumbers {
		packet := s.sentPackets[packetNumber]
		events.ackedBytes += packet.congestionBytes(quicDefaultMaxDatagramSize)
		s.removeSentPacket(packetNumber, packet)
		s.ackedPackets++
		delete(s.probeQueued, packetNumber)
	}
	events.merge(s.detectPacketThresholdLoss(frame.LargestAcknowledged))
	return events
}

func (s *quicLossRecoveryState) advance(now time.Time, largestAcked uint64, largestAckedSet bool) quicLossRecoveryEvents {
	if s == nil || len(s.sentPackets) == 0 || now.IsZero() {
		return quicLossRecoveryEvents{}
	}
	events := quicLossRecoveryEvents{}
	if largestAckedSet {
		events.merge(s.detectTimeThresholdLoss(now, largestAcked))
	}
	s.queueProbe(now)
	return events
}

func (s *quicLossRecoveryState) snapshot() QUICLossRecoverySnapshot {
	if s == nil {
		return QUICLossRecoverySnapshot{}
	}
	snapshot := QUICLossRecoverySnapshot{
		OutstandingPackets:    uint64(len(s.sentPackets)),
		AckElicitingInFlight:  s.ackElicitingInFlight,
		BytesInFlight:         s.bytesInFlight,
		AckedPackets:          s.ackedPackets,
		LostPackets:           s.lostPackets,
		RetransmissionsQueued: s.retransmissionsQueued,
		ProbeTimeouts:         s.probeTimeouts,
		LatestRTT:             s.latestRTT,
		SmoothedRTT:           s.smoothedRTT,
		RTTVariance:           s.rttVar,
	}
	if oldest, ok := s.oldestAckElicitingPacket(); ok {
		snapshot.PTOArmed = true
		snapshot.PTODeadline = oldest.SentAt.Add(s.probeTimeout())
	}
	return snapshot
}

func (s *quicLossRecoveryState) drainPendingRetransmissions() []QUICPendingRetransmission {
	if s == nil || len(s.pendingRetransmission) == 0 {
		return nil
	}
	out := make([]QUICPendingRetransmission, len(s.pendingRetransmission))
	for i, pending := range s.pendingRetransmission {
		out[i] = QUICPendingRetransmission{
			OriginalPacketNumber: pending.OriginalPacketNumber,
			Probe:                pending.Probe,
			Frames:               cloneQUICSentFrames(pending.Frames),
		}
	}
	s.pendingRetransmission = nil
	return out
}

func (s *quicLossRecoveryState) detectPacketThresholdLoss(largestAcked uint64) quicLossRecoveryEvents {
	if s == nil || largestAcked == 0 {
		return quicLossRecoveryEvents{}
	}
	lostPacketNumbers := make([]uint64, 0, len(s.sentPackets))
	for packetNumber, packet := range s.sentPackets {
		if packetNumber+quicPacketLossThreshold > largestAcked {
			continue
		}
		lostPacketNumbers = append(lostPacketNumbers, packetNumber)
		_ = packet
	}
	return s.queueLostPackets(lostPacketNumbers, false)
}

func (s *quicLossRecoveryState) detectTimeThresholdLoss(now time.Time, largestAcked uint64) quicLossRecoveryEvents {
	if s == nil || largestAcked == 0 {
		return quicLossRecoveryEvents{}
	}
	lossDelay := s.lossDelay()
	lostPacketNumbers := make([]uint64, 0, len(s.sentPackets))
	for packetNumber, packet := range s.sentPackets {
		if packetNumber > largestAcked {
			continue
		}
		if packet.SentAt.IsZero() || now.Before(packet.SentAt) {
			continue
		}
		if now.Sub(packet.SentAt) < lossDelay {
			continue
		}
		lostPacketNumbers = append(lostPacketNumbers, packetNumber)
	}
	return s.queueLostPackets(lostPacketNumbers, false)
}

func (s *quicLossRecoveryState) queueProbe(now time.Time) {
	if s == nil {
		return
	}
	oldest, ok := s.oldestAckElicitingPacket()
	if !ok || oldest.SentAt.IsZero() || now.Before(oldest.SentAt) {
		return
	}
	if now.Sub(oldest.SentAt) < s.probeTimeout() {
		return
	}
	if s.probeQueued == nil {
		s.probeQueued = make(map[uint64]struct{})
	}
	if _, exists := s.probeQueued[oldest.PacketNumber]; exists {
		return
	}
	s.pendingRetransmission = append(s.pendingRetransmission, QUICPendingRetransmission{
		OriginalPacketNumber: oldest.PacketNumber,
		Probe:                true,
		Frames:               cloneQUICSentFrames(oldest.Frames),
	})
	s.probeQueued[oldest.PacketNumber] = struct{}{}
	s.retransmissionsQueued++
	s.probeTimeouts++
}

func (s *quicLossRecoveryState) queueLostPackets(packetNumbers []uint64, probe bool) quicLossRecoveryEvents {
	events := quicLossRecoveryEvents{}
	if s == nil || len(packetNumbers) == 0 {
		return events
	}
	sort.Slice(packetNumbers, func(i, j int) bool { return packetNumbers[i] < packetNumbers[j] })
	for _, packetNumber := range packetNumbers {
		packet, ok := s.sentPackets[packetNumber]
		if !ok {
			continue
		}
		events.lostBytes += packet.congestionBytes(quicDefaultMaxDatagramSize)
		if packet.SentAt.After(events.largestLostSentAt) {
			events.largestLostSentAt = packet.SentAt
		}
		s.pendingRetransmission = append(s.pendingRetransmission, QUICPendingRetransmission{
			OriginalPacketNumber: packet.PacketNumber,
			Probe:                probe,
			Frames:               cloneQUICSentFrames(packet.Frames),
		})
		s.removeSentPacket(packetNumber, packet)
		s.lostPackets++
		s.retransmissionsQueued++
		delete(s.probeQueued, packetNumber)
	}
	return events
}

func (e *quicLossRecoveryEvents) merge(other quicLossRecoveryEvents) {
	if e == nil {
		return
	}
	e.ackedBytes += other.ackedBytes
	e.lostBytes += other.lostBytes
	if other.largestAckedSentAt.After(e.largestAckedSentAt) {
		e.largestAckedSentAt = other.largestAckedSentAt
	}
	if other.largestLostSentAt.After(e.largestLostSentAt) {
		e.largestLostSentAt = other.largestLostSentAt
	}
}

func (s *quicLossRecoveryState) removeSentPacket(packetNumber uint64, packet QUICSentPacket) {
	delete(s.sentPackets, packetNumber)
	if packet.AckEliciting {
		if s.ackElicitingInFlight > 0 {
			s.ackElicitingInFlight--
		}
		payloadBytes := packet.payloadBytes()
		if s.bytesInFlight >= payloadBytes {
			s.bytesInFlight -= payloadBytes
		} else {
			s.bytesInFlight = 0
		}
	}
}

func (s *quicLossRecoveryState) oldestAckElicitingPacket() (QUICSentPacket, bool) {
	if s == nil {
		return QUICSentPacket{}, false
	}
	var oldest QUICSentPacket
	found := false
	for _, packet := range s.sentPackets {
		if !packet.AckEliciting {
			continue
		}
		if !found || packet.SentAt.Before(oldest.SentAt) || (packet.SentAt.Equal(oldest.SentAt) && packet.PacketNumber < oldest.PacketNumber) {
			oldest = packet
			found = true
		}
	}
	return oldest, found
}

func (s *quicLossRecoveryState) lossDelay() time.Duration {
	baseRTT := maxDuration(s.latestRTT, s.smoothedRTT)
	if baseRTT <= 0 {
		baseRTT = quicInitialRTT
	}
	lossDelay := (baseRTT * 9) / 8
	if lossDelay < quicTimerGranularity {
		lossDelay = quicTimerGranularity
	}
	return lossDelay
}

func (s *quicLossRecoveryState) probeTimeout() time.Duration {
	if s.smoothedRTT > 0 {
		return maxDuration(s.smoothedRTT+maxDuration(4*s.rttVar, quicTimerGranularity), quicTimerGranularity)
	}
	if s.latestRTT > 0 {
		return maxDuration(2*s.latestRTT, quicTimerGranularity)
	}
	return 2 * quicInitialRTT
}

func (s *quicLossRecoveryState) updateRTT(sample time.Duration) {
	if sample < 0 {
		return
	}
	s.latestRTT = sample
	if s.smoothedRTT == 0 {
		s.smoothedRTT = sample
		s.rttVar = sample / 2
		return
	}
	delta := s.smoothedRTT - sample
	if delta < 0 {
		delta = -delta
	}
	s.rttVar = (3*s.rttVar + delta) / 4
	s.smoothedRTT = (7*s.smoothedRTT + sample) / 8
}

func ackFrameContainsPacket(frame QUICAckFrame, packetNumber uint64) bool {
	for _, ackRange := range frame.Ranges {
		if packetNumber >= ackRange.Smallest && packetNumber <= ackRange.Largest {
			return true
		}
	}
	return false
}

func cloneQUICSentFrames(frames []QUICSentFrame) []QUICSentFrame {
	if len(frames) == 0 {
		return nil
	}
	out := make([]QUICSentFrame, len(frames))
	for i, frame := range frames {
		out[i] = QUICSentFrame{
			FrameType: frame.FrameType,
			StreamID:  frame.StreamID,
			Offset:    frame.Offset,
			Fin:       frame.Fin,
		}
		if len(frame.Payload) > 0 {
			out[i].Payload = append([]byte(nil), frame.Payload...)
		}
	}
	return out
}

func (p QUICSentPacket) payloadBytes() uint64 {
	var total uint64
	for _, frame := range p.Frames {
		total += uint64(len(frame.Payload))
	}
	return total
}

func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}
