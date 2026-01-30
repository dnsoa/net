package pinger

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type tcpPinger struct {
	port int
	d    net.Dialer
}

// TCPTarget is a TCP connect target.
type TCPTarget struct {
	Addr netip.Addr
	Port int
}

// TCPTargetResult is the outcome of a single TCP connect attempt.
type TCPTargetResult struct {
	Addr netip.Addr
	Port int
	RTT  time.Duration
	Err  error
}

// NewTCPPinger returns a Pinger that measures latency by establishing a TCP connection.
//
// This does not require ICMP privileges, but it measures connect latency to the given port,
// not ICMP echo RTT.
func NewTCPPinger(port int) Pinger {
	return &tcpPinger{port: port}
}

func (p *tcpPinger) Ping(ctx context.Context, addr netip.Addr) (time.Duration, error) {
	if !addr.IsValid() {
		return 0, ErrInvalidAddr
	}
	if p.port <= 0 || p.port > 65535 {
		return 0, fmt.Errorf("pinger: invalid tcp port: %d", p.port)
	}

	hostPort := net.JoinHostPort(addr.String(), strconv.Itoa(p.port))
	start := time.Now()
	c, err := p.d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return 0, err
	}
	_ = c.Close()
	return time.Since(start), nil
}

// PingAllTCP pings each address once using TCP connect to port.
func PingAllTCP(ctx context.Context, addrs []netip.Addr, port int, opts ...Option) ([]Result, error) {
	return PingAllWith(ctx, NewTCPPinger(port), addrs, opts...)
}

// PingAllTCPTargets pings each (ip, port) target once using TCP connect.
//
// Results are returned in the same order as input.
func PingAllTCPTargets(ctx context.Context, targets []TCPTarget, opts ...Option) ([]TCPTargetResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(targets) == 0 {
		return nil, ErrEmptyAddrs
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

	results := make([]TCPTargetResult, len(targets))

	workers := min(cfg.concurrency, len(targets))

	type job struct {
		idx int
		t   TCPTarget
	}
	jobs := make(chan job)

	var wg sync.WaitGroup

	for range workers {
		wg.Go(func() {
			var d net.Dialer
			for j := range jobs {
				t := j.t
				res := TCPTargetResult{Addr: t.Addr, Port: t.Port}
				if !t.Addr.IsValid() {
					res.Err = ErrInvalidAddr
					results[j.idx] = res
					continue
				}
				if t.Port <= 0 || t.Port > 65535 {
					res.Err = fmt.Errorf("pinger: invalid tcp port: %d", t.Port)
					results[j.idx] = res
					continue
				}

				pctx, cancel := context.WithTimeout(ctx, cfg.timeout)
				hostPort := net.JoinHostPort(t.Addr.String(), strconv.Itoa(t.Port))
				start := time.Now()
				c, err := d.DialContext(pctx, "tcp", hostPort)
				if err == nil {
					_ = c.Close()
					res.RTT = time.Since(start)
					res.Err = nil
				} else {
					res.Err = err
				}
				cancel()
				results[j.idx] = res
			}
		})
	}

	for i, t := range targets {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		case jobs <- job{idx: i, t: t}:
		}
	}
	close(jobs)
	wg.Wait()
	return results, nil
}

// ParseTCPTargets parses a list of strings into TCP connect targets.
//
// Supported forms:
//   - "1.2.3.4:80"
//   - "[2001:db8::1]:443"
//
// Hostnames are not supported; the host must be an IP address.
func ParseTCPTargets(values []string) ([]TCPTarget, error) {
	out := make([]TCPTarget, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil, fmt.Errorf("pinger: empty target")
		}
		host, portStr, err := net.SplitHostPort(v)
		if err != nil {
			return nil, fmt.Errorf("pinger: invalid tcp target %q: %w", v, err)
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf("pinger: invalid ip %q in target %q: %w", host, v, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("pinger: invalid port %q in target %q: %w", portStr, v, err)
		}
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("pinger: invalid tcp port: %d", port)
		}
		out = append(out, TCPTarget{Addr: ip, Port: port})
	}
	return out, nil
}
