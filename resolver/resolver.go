// Package resolver provides DNS A/AAAA resolution with optional ECS and configurable upstreams.
package resolver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/phuslu/fastdns"
)

var (
	ErrEmptyDomain = errors.New("resolver: empty domain")
)

// ResolveA resolves the A records for the given domain.
//
// If ECS is provided via options, resolver will query once for each ECS prefix
// and return the union of all returned IPs.
func ResolveA(domain string, opts ...Option) ([]netip.Addr, error) {
	return resolve(domain, "ip4", opts...)
}

// ResolveAAAA resolves the AAAA records for the given domain.
//
// If ECS is provided via options, resolver will query once for each ECS prefix
// and return the union of all returned IPs.
func ResolveAAAA(domain string, opts ...Option) ([]netip.Addr, error) {
	return resolve(domain, "ip6", opts...)
}

func resolve(domain, network string, opts ...Option) ([]netip.Addr, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, ErrEmptyDomain
	}

	config := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&config)
		}
	}
	if config.ecsErr != nil {
		return nil, config.ecsErr
	}
	if config.upstreamErr != nil {
		return nil, config.upstreamErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.timeout)
	defer cancel()

	client, err := newClient(config)
	if err != nil {
		return nil, err
	}

	if len(config.ecs) == 0 {
		ips, err := client.LookupNetIP(ctx, network, domain)
		if err != nil {
			return nil, err
		}
		return uniqueAddrs(ips), nil
	}

	out := make([]netip.Addr, 0, 8)
	seen := make(map[netip.Addr]struct{}, 8)
	for _, prefix := range config.ecs {
		qctx := fastdns.WithClientSubnet(ctx, prefix)
		ips, err := client.LookupNetIP(qctx, network, domain)
		if err != nil {
			return nil, fmt.Errorf("resolver: lookup %s with ecs=%s: %w", domain, prefix.String(), err)
		}
		for _, ip := range ips {
			if ip.IsValid() {
				if _, ok := seen[ip]; ok {
					continue
				}
				seen[ip] = struct{}{}
				out = append(out, ip)
			}
		}
	}

	return out, nil
}

func newClient(config options) (*fastdns.Client, error) {
	if config.client != nil {
		return config.client, nil
	}

	switch config.upstreamKind {
	case upstreamUDP:
		addr := config.upstreamAddr
		if strings.TrimSpace(addr) == "" {
			addr = defaultNameServer()
		}
		return &fastdns.Client{
			Addr:    addr,
			Timeout: config.timeout,
		}, nil

	case upstreamTCP:
		addr := config.upstreamAddr
		if strings.TrimSpace(addr) == "" {
			addr = defaultNameServer()
		}
		d := &tcpDNSTransportDialer{Timeout: config.timeout}
		return &fastdns.Client{Addr: addr, Timeout: config.timeout, Dialer: d}, nil

	case upstreamDoT:
		addr := config.upstreamAddr
		if strings.TrimSpace(addr) == "" {
			return nil, fmt.Errorf("resolver: empty dot server")
		}
		tlsCfg := config.tlsConfig
		if tlsCfg == nil {
			host, _, _ := net.SplitHostPort(addr)
			tlsCfg = &tls.Config{ServerName: host}
		}
		d := &tcpDNSTransportDialer{Timeout: config.timeout, TLSConfig: tlsCfg}
		return &fastdns.Client{Addr: addr, Timeout: config.timeout, Dialer: d}, nil

	case upstreamDoH:
		ep := config.dohEndpoint
		if ep == nil {
			if strings.TrimSpace(config.upstreamAddr) == "" {
				return nil, fmt.Errorf("resolver: empty doh endpoint")
			}
			u, err := url.Parse(config.upstreamAddr)
			if err != nil {
				return nil, fmt.Errorf("resolver: invalid doh endpoint: %w", err)
			}
			ep = u
		}
		d := &fastdns.HTTPDialer{Endpoint: ep}
		if config.httpTransport != nil {
			d.Transport = config.httpTransport
		}
		return &fastdns.Client{Timeout: config.timeout, Dialer: d}, nil

	default:
		return nil, fmt.Errorf("resolver: unknown upstream kind: %d", config.upstreamKind)
	}
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

var (
	defaultNameServer = sync.OnceValue(func() string {
		v := readFirstResolvConfNameServer("/etc/resolv.conf")
		if v == "" {
			v = net.JoinHostPort("1.1.1.1", "53")
		}
		return v
	})
)

func readFirstResolvConfNameServer(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Typical lines:
	// nameserver 1.1.1.1
	// nameserver 2606:4700:4700::1111
	re := regexp.MustCompile(`(?m)^\s*nameserver\s+(\S+)\s*$`)
	m := re.FindStringSubmatch(string(data))
	if len(m) != 2 {
		return ""
	}
	// Ensure it has a port.
	host := strings.TrimSpace(m[1])
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "53")
}
