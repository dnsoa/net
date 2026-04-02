package http3

import "time"

type QUICKeepAliveSnapshot struct {
	LastActivityAt   time.Time
	LastReceiveAt    time.Time
	LastSendAt       time.Time
	LastPingSentAt   time.Time
	LastPingQueuedAt time.Time
	PingFramesSeen   uint64
	PingFramesSent   uint64
	PendingPing      bool
}

type quicKeepAliveState struct {
	lastActivityAt   time.Time
	lastReceiveAt    time.Time
	lastSendAt       time.Time
	lastPingSentAt   time.Time
	lastPingQueuedAt time.Time
	pingFramesSeen   uint64
	pingFramesSent   uint64
	pendingPing      bool
}

func (s *quicKeepAliveState) observeReceive(now time.Time) {
	if s == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.lastReceiveAt = now
	s.lastActivityAt = now
}

func (s *quicKeepAliveState) observeSend(now time.Time) {
	if s == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.lastSendAt = now
	s.lastActivityAt = now
}

func (s *quicKeepAliveState) observePing(now time.Time) {
	if s == nil {
		return
	}
	s.pingFramesSeen++
	s.observeReceive(now)
}

func (s *quicKeepAliveState) arm(now time.Time, interval time.Duration) bool {
	if s == nil || interval <= 0 {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	if s.lastActivityAt.IsZero() {
		s.lastActivityAt = now
		return false
	}
	if s.pendingPing {
		return false
	}
	if now.Sub(s.lastActivityAt) < interval {
		return false
	}
	s.pendingPing = true
	s.lastPingQueuedAt = now
	return true
}

func (s *quicKeepAliveState) drainPingFrame(now time.Time) []byte {
	if s == nil || !s.pendingPing {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.pendingPing = false
	s.pingFramesSent++
	s.lastPingSentAt = now
	s.observeSend(now)
	return []byte{quicFrameTypePing}
}

func (s *quicKeepAliveState) isIdle(now time.Time, timeout time.Duration) bool {
	if s == nil || timeout <= 0 {
		return false
	}
	if s.lastActivityAt.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	return now.Sub(s.lastActivityAt) >= timeout
}

func (s *quicKeepAliveState) snapshot() QUICKeepAliveSnapshot {
	if s == nil {
		return QUICKeepAliveSnapshot{}
	}
	return QUICKeepAliveSnapshot{
		LastActivityAt:   s.lastActivityAt,
		LastReceiveAt:    s.lastReceiveAt,
		LastSendAt:       s.lastSendAt,
		LastPingSentAt:   s.lastPingSentAt,
		LastPingQueuedAt: s.lastPingQueuedAt,
		PingFramesSeen:   s.pingFramesSeen,
		PingFramesSent:   s.pingFramesSent,
		PendingPing:      s.pendingPing,
	}
}
