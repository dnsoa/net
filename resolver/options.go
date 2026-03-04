package resolver

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type options struct {
	timeout       time.Duration
	ecs           []netip.Prefix
	ecsErr        error
	httpTransport http.RoundTripper
	debug         bool
}

func defaultOptions() options {
	return options{
		timeout: 5 * time.Second,
	}
}

// Option configures resolver behavior.
type Option func(*options)

// WithTimeout sets the per-query timeout.
func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.timeout = d
		}
	}
}

// WithECS configures an EDNS Client Subnet (ECS) prefix list.
//
// Each entry can be a CIDR prefix ("1.2.3.0/24") or a single IP ("43.242.1.24").
// For a single IP the default mask is /24 (IPv4) or /56 (IPv6).
//
// On each DNS query the resolver randomly picks one prefix from the list,
// which makes it ideal for CDN domains with smart / geo-aware resolution.
func WithECS(prefixes ...string) Option {
	return func(o *options) {
		if len(prefixes) == 0 {
			o.ecs = nil
			o.ecsErr = nil
			return
		}
		ecs, err := parseECS(prefixes)
		if err != nil {
			o.ecs = nil
			o.ecsErr = fmt.Errorf("resolver: invalid ecs: %w", err)
			return
		}
		o.ecs = ecs
		o.ecsErr = nil
	}
}

// WithHTTPTransport customizes the HTTP transport used for DoH queries.
func WithHTTPTransport(rt http.RoundTripper) Option {
	return func(o *options) {
		if rt != nil {
			o.httpTransport = rt
		}
	}
}

// WithDebug enables debug logging. When enabled, the resolver prints
// DNS query details (domain, network, ECS prefix) and results (IPs or errors)
// as well as dial connection attempts to slog at Debug level.
func WithDebug(on bool) Option {
	return func(o *options) {
		o.debug = on
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func parseECS(prefixes []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, s := range prefixes {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, fmt.Errorf("empty prefix")
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			// Allow a bare IP — default /24 for IPv4, /56 for IPv6.
			addr, addrErr := netip.ParseAddr(s)
			if addrErr != nil {
				return nil, err
			}
			bits := 56
			if addr.Is4() {
				bits = 24
			}
			p = netip.PrefixFrom(addr, bits)
		}
		p = p.Masked()
		if !p.IsValid() {
			return nil, fmt.Errorf("invalid prefix: %q", s)
		}
		out = append(out, p)
	}
	return out, nil
}
