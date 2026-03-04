// Package resolver provides a simple DNS resolver using DoH (DNS over HTTPS)
// with ECS (EDNS Client Subnet) support for CDN-friendly smart resolution.
//
// When an ECS list is configured, each query randomly picks one prefix so that
// repeated lookups for the same CDN domain return region-aware answers.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/phuslu/fastdns"
)

var ErrEmptyDomain = errors.New("resolver: empty domain")

// Common DoH endpoints.
const (
	DoHCloudflare = "https://cloudflare-dns.com/dns-query"
	DoHGoogle     = "https://dns.google/dns-query"
	DoHQuad9      = "https://dns.quad9.net/dns-query"
	DoHDnspod     = "https://sm2.doh.pub/dns-query"
	DoH360        = "https://doh.360.cn/dns-query"
)

// Resolver resolves DNS via DoH with optional ECS support.
type Resolver struct {
	client *fastdns.Client
	cfg    options

	rngMu sync.Mutex
	rng   *rand.Rand

	// lookupFn, if non-nil, overrides the default DNS lookup (used in tests).
	lookupFn func(ctx context.Context, network, domain string) ([]netip.Addr, error)
}

// New creates a Resolver that resolves DNS via DoH (DNS over HTTPS).
//
// dohEndpoint is the DoH URL, e.g. "https://cloudflare-dns.com/dns-query".
func New(dohEndpoint string, opts ...Option) (*Resolver, error) {
	cfg := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.ecsErr != nil {
		return nil, cfg.ecsErr
	}

	dohEndpoint = strings.TrimSpace(dohEndpoint)
	if dohEndpoint == "" {
		return nil, errors.New("resolver: empty doh endpoint")
	}
	u, err := url.Parse(dohEndpoint)
	if err != nil {
		return nil, fmt.Errorf("resolver: invalid doh endpoint: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("resolver: unsupported doh scheme: %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("resolver: doh endpoint missing host")
	}

	d := &fastdns.HTTPDialer{Endpoint: u}
	if cfg.httpTransport != nil {
		d.Transport = cfg.httpTransport
	}
	client := &fastdns.Client{Timeout: cfg.timeout, Dialer: d}

	return &Resolver{
		client: client,
		cfg:    cfg,
		rng:    rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), uint64(time.Now().UnixNano())^0x9e3779b97f4a7c15)),
	}, nil
}

// LookupHost resolves host to a list of IP strings (both A and AAAA).
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	ips, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out, nil
}

// LookupNetIP resolves host to IPs.
//
// Supported networks: "ip" (both), "ip4", "ip6".
// If ECS is configured, a random prefix from the list is attached to the query.
func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, ErrEmptyDomain
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}

	host = normalizeDomain(host)
	if host == "" {
		return nil, ErrEmptyDomain
	}

	switch network {
	case "ip4", "ip6":
		return r.lookup(ctx, network, host)
	case "ip":
		v6, err6 := r.lookup(ctx, "ip6", host)
		v4, err4 := r.lookup(ctx, "ip4", host)
		// IPv6 first for dual-stack preference.
		out := make([]netip.Addr, 0, len(v6)+len(v4))
		out = append(out, v6...)
		out = append(out, v4...)
		out = uniqueAddrs(out)
		if len(out) > 0 {
			return out, nil
		}
		if err6 != nil {
			return nil, err6
		}
		return nil, err4
	default:
		return nil, fmt.Errorf("resolver: unsupported network: %q", network)
	}
}

// DialContext resolves the hostname in address via DoH then dials.
// Suitable for use as http.Transport.DialContext.
func (r *Resolver) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") && !strings.HasPrefix(network, "udp") {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, errors.New("resolver: empty host")
	}

	// Already an IP — dial directly.
	if addr, err := netip.ParseAddr(host); err == nil {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
	}

	ipNet := ipNetworkForDial(network)

	// For dual-stack networks, prefer IPv6: try v6 candidates first,
	// then fall back to v4.
	if ipNet == "ip" {
		return r.dialPreferV6(ctx, network, host, port)
	}

	ips, err := r.LookupNetIP(ctx, ipNet, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolver: no ip records for %s", host)
	}
	return r.dialCandidates(ctx, network, host, port, r.shuffledCopy(ips))
}

// ---------------------------------------------------------------------------
// internal
// ---------------------------------------------------------------------------

// dialPreferV6 resolves both address families and tries IPv6 first,
// then falls back to IPv4 if all v6 candidates fail.
func (r *Resolver) dialPreferV6(ctx context.Context, network, host, port string) (net.Conn, error) {
	v6, err6 := r.lookup(ctx, "ip6", host)
	v4, err4 := r.lookup(ctx, "ip4", host)

	v6 = r.shuffledCopy(v6)
	v4 = r.shuffledCopy(v4)

	// Try v6 first.
	if len(v6) > 0 {
		conn, err := r.dialCandidates(ctx, network, host, port, v6)
		if err == nil {
			return conn, nil
		}
	}
	// Fall back to v4.
	if len(v4) > 0 {
		return r.dialCandidates(ctx, network, host, port, v4)
	}
	// No candidates at all.
	if err6 != nil {
		return nil, err6
	}
	if err4 != nil {
		return nil, err4
	}
	return nil, fmt.Errorf("resolver: no ip records for %s", host)
}

// dialCandidates tries each IP in order until one connects.
func (r *Resolver) dialCandidates(ctx context.Context, network, host, port string, ips []netip.Addr) (net.Conn, error) {
	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), port)
		if r.cfg.debug {
			slog.Debug("resolver: dialing", "network", network, "host", host, "addr", addr)
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err == nil {
			if r.cfg.debug {
				slog.Debug("resolver: dial success", "network", network, "host", host, "addr", addr,
					"local", conn.LocalAddr(), "remote", conn.RemoteAddr())
			}
			return conn, nil
		}
		if r.cfg.debug {
			slog.Debug("resolver: dial failed", "network", network, "host", host, "addr", addr, "error", err)
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("resolver: dial failed for %s:%s", host, port)
	}
	return nil, lastErr
}

// lookup performs a single DNS query with optional random ECS.
func (r *Resolver) lookup(ctx context.Context, network, domain string) ([]netip.Addr, error) {
	// Test hook.
	if r.lookupFn != nil {
		return r.lookupFn(ctx, network, domain)
	}

	if r.cfg.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.cfg.timeout)
		defer cancel()
	}

	// Attach a random ECS prefix if configured.
	var ecsPrefix netip.Prefix
	if len(r.cfg.ecs) > 0 {
		ecsPrefix = r.randomECS()
		ctx = fastdns.WithClientSubnet(ctx, ecsPrefix)
	}

	if r.cfg.debug {
		if ecsPrefix.IsValid() {
			slog.Debug("resolver: lookup", "network", network, "domain", domain, "ecs", ecsPrefix.String())
		} else {
			slog.Debug("resolver: lookup", "network", network, "domain", domain)
		}
	}

	ips, err := r.client.LookupNetIP(ctx, network, domain)
	if err != nil {
		if r.cfg.debug {
			slog.Debug("resolver: lookup failed", "network", network, "domain", domain, "error", err)
		}
		return nil, err
	}
	ips = uniqueAddrs(ips)
	if r.cfg.debug {
		slog.Debug("resolver: lookup result", "network", network, "domain", domain, "ips", ips)
	}
	return ips, nil
}

// randomECS picks one ECS prefix at random from the configured list.
func (r *Resolver) randomECS() netip.Prefix {
	r.rngMu.Lock()
	idx := r.rng.IntN(len(r.cfg.ecs))
	r.rngMu.Unlock()
	return r.cfg.ecs[idx]
}

func (r *Resolver) shuffledCopy(in []netip.Addr) []netip.Addr {
	if len(in) <= 1 {
		return append([]netip.Addr(nil), in...)
	}
	out := make([]netip.Addr, len(in))
	copy(out, in)
	r.rngMu.Lock()
	r.rng.Shuffle(len(out), func(i, j int) {
		out[i], out[j] = out[j], out[i]
	})
	r.rngMu.Unlock()
	return out
}

func ipNetworkForDial(network string) string {
	if strings.HasSuffix(network, "4") {
		return "ip4"
	}
	if strings.HasSuffix(network, "6") {
		return "ip6"
	}
	return "ip"
}

func uniqueAddrs(ips []netip.Addr) []netip.Addr {
	if len(ips) <= 1 {
		return ips
	}
	seen := make(map[netip.Addr]struct{}, len(ips))
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")
	return domain
}
