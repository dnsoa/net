package http3

import (
	"fmt"
	"io"
	"sort"
)

const (
	quicFrameTypeAck    byte = 0x02
	quicFrameTypeAckECN byte = 0x03
)

type QUICPacketNumberSpace uint8

const (
	QUICPacketNumberSpaceUnknown QUICPacketNumberSpace = iota
	QUICPacketNumberSpaceInitial
	QUICPacketNumberSpaceHandshake
	QUICPacketNumberSpaceApplication
)

func (s QUICPacketNumberSpace) String() string {
	switch s {
	case QUICPacketNumberSpaceInitial:
		return "initial"
	case QUICPacketNumberSpaceHandshake:
		return "handshake"
	case QUICPacketNumberSpaceApplication:
		return "application"
	default:
		return "unknown"
	}
}

type QUICAckRange struct {
	Smallest uint64
	Largest  uint64
}

type QUICAckECNCounts struct {
	ECT0 uint64
	ECT1 uint64
	CE   uint64
}

type QUICAckFrame struct {
	LargestAcknowledged uint64
	AckDelay            uint64
	Ranges              []QUICAckRange
	ECNCounts           *QUICAckECNCounts
}

type QUICPacketNumberSpaceSnapshot struct {
	LargestReceived uint64
	LargestAcked    uint64
	ReceivedPackets uint64
	AckFramesSeen   uint64
	PendingAck      bool
	AckRanges       []QUICAckRange
	LossRecovery    QUICLossRecoverySnapshot
}

type quicPacketNumberSpaceState struct {
	largestReceived    uint64
	largestReceivedSet bool
	largestAcked       uint64
	largestAckedSet    bool
	receivedPackets    uint64
	ackFramesSeen      uint64
	pendingAck         bool
	ackRanges          []QUICAckRange
	recovery           quicLossRecoveryState
}

func packetNumberSpaceForPacketType(packetType QUICPacketType) (QUICPacketNumberSpace, bool) {
	switch packetType {
	case QUICPacketTypeInitial:
		return QUICPacketNumberSpaceInitial, true
	case QUICPacketTypeHandshake:
		return QUICPacketNumberSpaceHandshake, true
	case QUICPacketTypeZeroRTT, QUICPacketTypeOneRTT:
		return QUICPacketNumberSpaceApplication, true
	default:
		return QUICPacketNumberSpaceUnknown, false
	}
}

func ParseQUICAckFrame(payload []byte) (QUICAckFrame, int, error) {
	if len(payload) == 0 {
		return QUICAckFrame{}, 0, io.EOF
	}
	frameType := payload[0]
	if frameType != quicFrameTypeAck && frameType != quicFrameTypeAckECN {
		return QUICAckFrame{}, 0, fmt.Errorf("http3 invalid ack frame type 0x%x", frameType)
	}
	offset := 1
	largestAcknowledged, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return QUICAckFrame{}, 0, err
	}
	offset += n
	ackDelay, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return QUICAckFrame{}, 0, err
	}
	offset += n
	ackRangeCount, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return QUICAckFrame{}, 0, err
	}
	offset += n
	firstAckRange, n, err := DecodeVarInt(payload[offset:])
	if err != nil {
		return QUICAckFrame{}, 0, err
	}
	offset += n
	if firstAckRange > largestAcknowledged {
		return QUICAckFrame{}, 0, fmt.Errorf("http3 invalid ack range: largest=%d first=%d", largestAcknowledged, firstAckRange)
	}
	ranges := make([]QUICAckRange, 0, ackRangeCount+1)
	currentLargest := largestAcknowledged
	currentSmallest := currentLargest - firstAckRange
	ranges = append(ranges, QUICAckRange{Smallest: currentSmallest, Largest: currentLargest})
	for i := uint64(0); i < ackRangeCount; i++ {
		gap, read, err := DecodeVarInt(payload[offset:])
		if err != nil {
			return QUICAckFrame{}, 0, err
		}
		offset += read
		ackRangeLength, read, err := DecodeVarInt(payload[offset:])
		if err != nil {
			return QUICAckFrame{}, 0, err
		}
		offset += read
		if currentSmallest < gap+2 {
			return QUICAckFrame{}, 0, fmt.Errorf("http3 invalid ack gap: smallest=%d gap=%d", currentSmallest, gap)
		}
		currentLargest = currentSmallest - gap - 2
		if ackRangeLength > currentLargest {
			return QUICAckFrame{}, 0, fmt.Errorf("http3 invalid ack range length: largest=%d range=%d", currentLargest, ackRangeLength)
		}
		currentSmallest = currentLargest - ackRangeLength
		ranges = append(ranges, QUICAckRange{Smallest: currentSmallest, Largest: currentLargest})
	}
	frame := QUICAckFrame{
		LargestAcknowledged: largestAcknowledged,
		AckDelay:            ackDelay,
		Ranges:              ranges,
	}
	if frameType == quicFrameTypeAckECN {
		ect0, read, err := DecodeVarInt(payload[offset:])
		if err != nil {
			return QUICAckFrame{}, 0, err
		}
		offset += read
		ect1, read, err := DecodeVarInt(payload[offset:])
		if err != nil {
			return QUICAckFrame{}, 0, err
		}
		offset += read
		ce, read, err := DecodeVarInt(payload[offset:])
		if err != nil {
			return QUICAckFrame{}, 0, err
		}
		offset += read
		frame.ECNCounts = &QUICAckECNCounts{ECT0: ect0, ECT1: ect1, CE: ce}
	}
	return frame, offset, nil
}

func AppendQUICAckFrame(dst []byte, ackDelay uint64, ranges []QUICAckRange) ([]byte, error) {
	normalized, err := normalizeAckRanges(ranges)
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("http3 ack frame requires at least one range")
	}
	dst = append(dst, quicFrameTypeAck)
	first := normalized[0]
	dst, err = AppendVarInt(dst, first.Largest)
	if err != nil {
		return nil, err
	}
	dst, err = AppendVarInt(dst, ackDelay)
	if err != nil {
		return nil, err
	}
	dst, err = AppendVarInt(dst, uint64(len(normalized)-1))
	if err != nil {
		return nil, err
	}
	dst, err = AppendVarInt(dst, first.Largest-first.Smallest)
	if err != nil {
		return nil, err
	}
	previous := first
	for _, current := range normalized[1:] {
		if previous.Smallest < current.Largest+2 {
			return nil, fmt.Errorf("http3 invalid ack range ordering: prev=%+v current=%+v", previous, current)
		}
		gap := previous.Smallest - current.Largest - 2
		dst, err = AppendVarInt(dst, gap)
		if err != nil {
			return nil, err
		}
		dst, err = AppendVarInt(dst, current.Largest-current.Smallest)
		if err != nil {
			return nil, err
		}
		previous = current
	}
	return dst, nil
}

func normalizeAckRanges(ranges []QUICAckRange) ([]QUICAckRange, error) {
	if len(ranges) == 0 {
		return nil, nil
	}
	normalized := make([]QUICAckRange, len(ranges))
	copy(normalized, ranges)
	for i := range normalized {
		if normalized[i].Smallest > normalized[i].Largest {
			return nil, fmt.Errorf("http3 invalid ack range: smallest=%d largest=%d", normalized[i].Smallest, normalized[i].Largest)
		}
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Largest == normalized[j].Largest {
			return normalized[i].Smallest > normalized[j].Smallest
		}
		return normalized[i].Largest > normalized[j].Largest
	})
	merged := normalized[:0]
	for _, current := range normalized {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		last := &merged[len(merged)-1]
		if last.Smallest <= current.Largest+1 {
			if current.Smallest < last.Smallest {
				last.Smallest = current.Smallest
			}
			if current.Largest > last.Largest {
				last.Largest = current.Largest
			}
			continue
		}
		merged = append(merged, current)
	}
	out := make([]QUICAckRange, len(merged))
	copy(out, merged)
	return out, nil
}

func (s *quicPacketNumberSpaceState) observePacket(rawPacketNumber uint64, packetNumberLength int) {
	if s == nil || packetNumberLength <= 0 {
		return
	}
	packetNumber := rawPacketNumber
	if s.largestReceivedSet {
		packetNumber = expandQUICPacketNumber(s.largestReceived, rawPacketNumber, packetNumberLength)
	}
	normalized, err := normalizeAckRanges(append(s.ackRanges, QUICAckRange{Smallest: packetNumber, Largest: packetNumber}))
	if err != nil {
		return
	}
	added := !ackRangesEqual(normalized, s.ackRanges)
	s.ackRanges = normalized
	if added {
		s.receivedPackets++
	}
	if !s.largestReceivedSet || packetNumber > s.largestReceived {
		s.largestReceived = packetNumber
		s.largestReceivedSet = true
	}
	s.pendingAck = true
}

func (s *quicPacketNumberSpaceState) observeAck(frame QUICAckFrame) {
	if s == nil {
		return
	}
	s.ackFramesSeen++
	if !s.largestAckedSet || frame.LargestAcknowledged > s.largestAcked {
		s.largestAcked = frame.LargestAcknowledged
		s.largestAckedSet = true
	}
}

func (s *quicPacketNumberSpaceState) snapshot() QUICPacketNumberSpaceSnapshot {
	if s == nil {
		return QUICPacketNumberSpaceSnapshot{}
	}
	snapshot := QUICPacketNumberSpaceSnapshot{
		LargestReceived: s.largestReceived,
		LargestAcked:    s.largestAcked,
		ReceivedPackets: s.receivedPackets,
		AckFramesSeen:   s.ackFramesSeen,
		PendingAck:      s.pendingAck,
		LossRecovery:    s.recovery.snapshot(),
	}
	if len(s.ackRanges) > 0 {
		snapshot.AckRanges = make([]QUICAckRange, len(s.ackRanges))
		copy(snapshot.AckRanges, s.ackRanges)
	}
	return snapshot
}

func (s *quicPacketNumberSpaceState) drainAckFrame() ([]byte, error) {
	if s == nil || !s.pendingAck || len(s.ackRanges) == 0 {
		return nil, nil
	}
	frame, err := AppendQUICAckFrame(nil, 0, s.ackRanges)
	if err != nil {
		return nil, err
	}
	s.pendingAck = false
	return frame, nil
}

func expandQUICPacketNumber(largestReceived uint64, truncated uint64, packetNumberLength int) uint64 {
	if packetNumberLength <= 0 {
		return truncated
	}
	pnBits := uint(packetNumberLength * 8)
	pnWindow := uint64(1) << pnBits
	pnHalfWindow := pnWindow / 2
	pnMask := pnWindow - 1
	expected := largestReceived + 1
	candidate := (expected & ^pnMask) | truncated
	if candidate+pnHalfWindow <= expected && candidate+pnWindow > candidate {
		candidate += pnWindow
	} else if candidate > expected+pnHalfWindow && candidate >= pnWindow {
		candidate -= pnWindow
	}
	return candidate
}

func ackRangesEqual(left, right []QUICAckRange) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
