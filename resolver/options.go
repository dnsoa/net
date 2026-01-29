package resolver

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/phuslu/fastdns"
)

type upstreamKind uint8

const (
	upstreamUDP upstreamKind = iota
	upstreamTCP
	upstreamDoT
	upstreamDoH
)

type options struct {
	ecs     []netip.Prefix
	ecsErr  error
	timeout time.Duration

	upstreamKind upstreamKind
	upstreamAddr string

	dohEndpoint   *url.URL
	httpTransport http.RoundTripper

	tlsConfig *tls.Config

	client *fastdns.Client

	upstreamErr error
}

func defaultOptions() options {
	return options{
		timeout:      3 * time.Second,
		upstreamKind: upstreamUDP,
	}
}

// Option configures resolver behavior.
type Option func(*options)

// WithECS configures an EDNS Client Subnet (ECS) prefix list.
//
// Each entry can be either a CIDR prefix (e.g. "1.2.3.0/24") or a single IP
// (e.g. "43.242.1.24"). For a single IP, resolver will use a default mask:
// IPv4 => /24, IPv6 => /56.
//
// When provided, resolver will query once per prefix and merge results.
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
			o.ecsErr = fmt.Errorf("resolver: invalid ecs prefix: %w", err)
			return
		}
		o.ecs = ecs
		o.ecsErr = nil
	}
}

// WithTimeout sets the overall resolve timeout (applies to all attempts, including ECS fanout).
//
// If d <= 0, it is treated as invalid.
func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		if d <= 0 {
			o.upstreamErr = fmt.Errorf("resolver: invalid timeout: %v", d)
			return
		}
		o.timeout = d
	}
}

// WithDNSServer sets a UDP DNS upstream (e.g. "1.1.1.1", "1.1.1.1:53", "dns.google:53").
//
// If addr is empty, it resets to the default from /etc/resolv.conf.
func WithDNSServer(addr string) Option {
	return func(o *options) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			o.upstreamKind = upstreamUDP
			o.upstreamAddr = ""
			o.upstreamErr = nil
			return
		}
		addr, err := ensureHostPort(addr, "53")
		if err != nil {
			o.upstreamErr = fmt.Errorf("resolver: invalid dns server: %w", err)
			return
		}
		o.upstreamKind = upstreamUDP
		o.upstreamAddr = addr
		o.dohEndpoint = nil
		o.tlsConfig = nil
		o.upstreamErr = nil
	}
}

// WithTCPServer sets a plain TCP DNS upstream (default port 53).
func WithTCPServer(addr string) Option {
	return func(o *options) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			o.upstreamErr = fmt.Errorf("resolver: empty tcp server")
			return
		}
		addr, err := ensureHostPort(addr, "53")
		if err != nil {
			o.upstreamErr = fmt.Errorf("resolver: invalid tcp server: %w", err)
			return
		}
		o.upstreamKind = upstreamTCP
		o.upstreamAddr = addr
		o.dohEndpoint = nil
		o.tlsConfig = nil
		o.upstreamErr = nil
	}
}

// WithDoT sets a DNS-over-TLS (DoT) upstream (default port 853).
//
// It uses the host part of addr as TLS ServerName.
func WithDoT(addr string) Option {
	return WithDoTServerName(addr, "")
}

// WithDoTServerName sets a DoT upstream with an explicit TLS ServerName.
//
// If serverName is empty, it uses the host part of addr.
func WithDoTServerName(addr string, serverName string) Option {
	return func(o *options) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			o.upstreamErr = fmt.Errorf("resolver: empty dot server")
			return
		}
		addr, err := ensureHostPort(addr, "853")
		if err != nil {
			o.upstreamErr = fmt.Errorf("resolver: invalid dot server: %w", err)
			return
		}
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil || host == "" {
			o.upstreamErr = fmt.Errorf("resolver: invalid dot server: %q", addr)
			return
		}
		if serverName == "" {
			serverName = host
		}
		o.upstreamKind = upstreamDoT
		o.upstreamAddr = addr
		o.tlsConfig = &tls.Config{ServerName: serverName}
		o.dohEndpoint = nil
		o.upstreamErr = nil
	}
}

// WithDoH sets a DNS-over-HTTPS (DoH) upstream endpoint.
//
// Example: "https://1.1.1.1/dns-query".
func WithDoH(endpoint string) Option {
	return func(o *options) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			o.upstreamErr = fmt.Errorf("resolver: empty doh endpoint")
			return
		}
		u, err := url.Parse(endpoint)
		if err != nil {
			o.upstreamErr = fmt.Errorf("resolver: invalid doh endpoint: %w", err)
			return
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			o.upstreamErr = fmt.Errorf("resolver: unsupported doh scheme: %q", u.Scheme)
			return
		}
		if u.Host == "" {
			o.upstreamErr = fmt.Errorf("resolver: doh endpoint missing host")
			return
		}
		o.upstreamKind = upstreamDoH
		o.dohEndpoint = u
		o.upstreamAddr = endpoint
		o.tlsConfig = nil
		o.upstreamErr = nil
	}
}

// WithHTTPTransport customizes the DoH HTTP transport.
//
// It has effect only when used with WithDoH.
func WithHTTPTransport(rt http.RoundTripper) Option {
	return func(o *options) {
		if rt == nil {
			o.upstreamErr = fmt.Errorf("resolver: nil http transport")
			return
		}
		o.httpTransport = rt
	}
}

// WithClient uses a custom fastdns client. If set, it takes precedence over
// WithDNSServer/WithTCPServer/WithDoT/WithDoH.
func WithClient(c *fastdns.Client) Option {
	return func(o *options) {
		if c == nil {
			o.upstreamErr = fmt.Errorf("resolver: nil client")
			return
		}
		o.client = c
		o.upstreamErr = nil
	}
}

func parseECS(prefixes []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, s := range prefixes {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, fmt.Errorf("invalid prefix: %q", s)
		}

		p, err := netip.ParsePrefix(s)
		if err != nil {
			// Allow a single IP as shorthand: v4 => /24, v6 => /56.
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

func ensureHostPort(addr string, defaultPort string) (string, error) {
	if strings.TrimSpace(addr) == "" {
		return "", fmt.Errorf("empty addr")
	}
	if host, port, err := net.SplitHostPort(addr); err == nil {
		host = strings.TrimSpace(host)
		port = strings.TrimSpace(port)
		if host == "" || port == "" {
			return "", fmt.Errorf("empty host or port")
		}
		return net.JoinHostPort(host, port), nil
	}
	// If it contains ':' and isn't in host:port form, treat it as an IPv6 host.
	if strings.Contains(addr, ":") {
		return net.JoinHostPort(addr, defaultPort), nil
	}
	return net.JoinHostPort(addr, defaultPort), nil
}
