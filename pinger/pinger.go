// Package pinger provides a simple way to ping a group of IP addresses.
package pinger

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

var (
	ErrEmptyAddrs = errors.New("pinger: empty addrs")
)

// Result is the outcome of a single ping attempt.
type Result struct {
	Addr netip.Addr
	RTT  time.Duration
	Err  error
}

// Pinger performs a single ping.
//
// Implementations should respect ctx cancellation.
type Pinger interface {
	Ping(ctx context.Context, addr netip.Addr) (time.Duration, error)
}

// PingAll pings each address once and returns results in the same order as input.
func PingAll(ctx context.Context, addrs []netip.Addr, opts ...Option) ([]Result, error) {
	return PingAllWith(ctx, NewICMPPinger(), addrs, opts...)
}

// PingAllWith is like PingAll but uses the provided Pinger.
func PingAllWith(ctx context.Context, p Pinger, addrs []netip.Addr, opts ...Option) ([]Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(addrs) == 0 {
		return nil, ErrEmptyAddrs
	}
	if p == nil {
		return nil, errors.New("pinger: nil pinger")
	}

	cfg := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if err := cfg.validateCommon(); err != nil {
		return nil, err
	}
	if ip, ok := p.(*icmpPinger); ok {
		if err := cfg.validateICMP(); err != nil {
			return nil, err
		}
		ip.payloadSize = cfg.payloadSize
	}

	return pingGroup(ctx, p, addrs, cfg)
}
