package pinger

import (
	"fmt"
	"time"
)

type options struct {
	timeout     time.Duration
	concurrency int
	payloadSize int
}

func defaultOptions() options {
	return options{
		timeout:     1 * time.Second,
		concurrency: 64,
		payloadSize: 32,
	}
}

// Option configures pinger behavior.
type Option func(*options)

// WithTimeout sets the per-IP ping timeout.
//
// If d <= 0, it is treated as invalid.
func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		o.timeout = d
	}
}

// WithConcurrency sets the max number of concurrent ping attempts.
//
// If n <= 0, it is treated as invalid.
func WithConcurrency(n int) Option {
	return func(o *options) {
		o.concurrency = n
	}
}

// WithPayloadSize sets the ICMP echo payload size in bytes.
//
// Valid range: [0, 1400]. Values outside are treated as invalid.
func WithPayloadSize(n int) Option {
	return func(o *options) {
		o.payloadSize = n
	}
}

func (o options) validateCommon() error {
	if o.timeout <= 0 {
		return fmt.Errorf("pinger: invalid timeout: %v", o.timeout)
	}
	if o.concurrency <= 0 {
		return fmt.Errorf("pinger: invalid concurrency: %d", o.concurrency)
	}
	return nil
}

func (o options) validateICMP() error {
	if o.payloadSize < 0 || o.payloadSize > 1400 {
		return fmt.Errorf("pinger: invalid payload size: %d", o.payloadSize)
	}
	return nil
}
