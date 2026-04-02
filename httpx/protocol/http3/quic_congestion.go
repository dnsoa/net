package http3

import "time"

const (
	quicDefaultMaxDatagramSize  = 1200
	quicMinimumCongestionWindow = 2 * quicDefaultMaxDatagramSize
	quicInitialCongestionWindow = 10 * quicDefaultMaxDatagramSize
)

type QUICCongestionSnapshot struct {
	CongestionWindow   uint64
	SlowStartThreshold uint64
	BytesInFlight      uint64
	MaxDatagramSize    uint64
	CongestionEvents   uint64
	RecoveryStart      time.Time
	InRecovery         bool
}

type quicCongestionController struct {
	congestionWindow   uint64
	slowStartThreshold uint64
	bytesInFlight      uint64
	maxDatagramSize    uint64
	congestionEvents   uint64
	recoveryStart      time.Time
}

type quicLossRecoveryEvents struct {
	ackedBytes         uint64
	lostBytes          uint64
	largestAckedSentAt time.Time
	largestLostSentAt  time.Time
}

func (c *quicCongestionController) snapshot() QUICCongestionSnapshot {
	c.ensureDefaults()
	return QUICCongestionSnapshot{
		CongestionWindow:   c.congestionWindow,
		SlowStartThreshold: c.slowStartThreshold,
		BytesInFlight:      c.bytesInFlight,
		MaxDatagramSize:    c.maxDatagramSize,
		CongestionEvents:   c.congestionEvents,
		RecoveryStart:      c.recoveryStart,
		InRecovery:         !c.recoveryStart.IsZero(),
	}
}

func (c *quicCongestionController) onPacketSent(packet QUICSentPacket) {
	c.ensureDefaults()
	if !packet.AckEliciting {
		return
	}
	c.bytesInFlight += packet.congestionBytes(c.maxDatagramSize)
}

func (c *quicCongestionController) onPacketsAcked(events quicLossRecoveryEvents) {
	c.ensureDefaults()
	if events.ackedBytes == 0 {
		return
	}
	if c.bytesInFlight >= events.ackedBytes {
		c.bytesInFlight -= events.ackedBytes
	} else {
		c.bytesInFlight = 0
	}
	if !c.recoveryStart.IsZero() && !events.largestAckedSentAt.After(c.recoveryStart) {
		return
	}
	if c.congestionWindow < c.slowStartThreshold {
		c.congestionWindow += events.ackedBytes
		return
	}
	increment := (c.maxDatagramSize * events.ackedBytes) / c.congestionWindow
	if increment == 0 {
		increment = 1
	}
	c.congestionWindow += increment
}

func (c *quicCongestionController) onPacketsLost(events quicLossRecoveryEvents) {
	c.ensureDefaults()
	if events.lostBytes == 0 {
		return
	}
	if c.bytesInFlight >= events.lostBytes {
		c.bytesInFlight -= events.lostBytes
	} else {
		c.bytesInFlight = 0
	}
	if !c.recoveryStart.IsZero() && !events.largestLostSentAt.After(c.recoveryStart) {
		return
	}
	c.recoveryStart = events.largestLostSentAt
	c.slowStartThreshold = maxUint64(c.congestionWindow/2, quicMinimumCongestionWindow)
	c.congestionWindow = c.slowStartThreshold
	c.congestionEvents++
}

func (c *quicCongestionController) canSend(bytes uint64) bool {
	c.ensureDefaults()
	return c.bytesInFlight+bytes <= c.congestionWindow
}

func (c *quicCongestionController) availableWindow() uint64 {
	c.ensureDefaults()
	if c.bytesInFlight >= c.congestionWindow {
		return 0
	}
	return c.congestionWindow - c.bytesInFlight
}

func (c *quicCongestionController) ensureDefaults() {
	if c.maxDatagramSize == 0 {
		c.maxDatagramSize = quicDefaultMaxDatagramSize
	}
	if c.congestionWindow == 0 {
		c.congestionWindow = quicInitialCongestionWindow
	}
	if c.slowStartThreshold == 0 {
		c.slowStartThreshold = ^uint64(0)
	}
}

func (p QUICSentPacket) congestionBytes(defaultBytes uint64) uint64 {
	bytes := p.payloadBytes()
	if bytes > 0 {
		return bytes
	}
	return defaultBytes
}

func maxUint64(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}
