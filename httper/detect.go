// Package httper provides small helpers for HTTP capability detection.
package httper

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type options struct {
	timeout    time.Duration
	tlsConfig  *tls.Config
	httpClient *http.Client
	host       string
	ip         netip.Addr
	port       int
	err        error
}

// Option configures detection behavior.
type Option func(*options)

func defaultOptions() options {
	return options{timeout: 2 * time.Second}
}

// WithTimeout sets the overall detection timeout.
func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		if d <= 0 {
			o.err = fmt.Errorf("httper: invalid timeout: %v", d)
			return
		}
		o.timeout = d
	}
}

// WithTLSConfig sets the TLS config used for TLS handshakes and HTTPS requests.
//
// The config is cloned before use.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(o *options) {
		o.tlsConfig = cfg
	}
}

// WithHTTPClient sets the HTTP client used for HTTP/3 Alt-Svc detection.
//
// If provided, its transport/TLS settings are used as-is.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) {
		o.httpClient = c
	}
}

// WithHost overrides the hostname used for TLS SNI and HTTP Host header.
//
// If empty, the host from target is used.
func WithHost(host string) Option {
	return func(o *options) {
		host = strings.TrimSpace(host)
		if host == "" {
			o.host = ""
			return
		}
		o.host = host
	}
}

// WithIP overrides the IP address used for the underlying TCP dial.
//
// This is useful when you want to probe a domain but connect to a specific IP.
func WithIP(ip string) Option {
	return func(o *options) {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			o.ip = netip.Addr{}
			return
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			o.err = fmt.Errorf("httper: invalid ip: %w", err)
			return
		}
		o.ip = addr
	}
}

// WithPort overrides the TCP port used for the underlying dial.
func WithPort(port int) Option {
	return func(o *options) {
		if port == 0 {
			o.port = 0
			return
		}
		if port < 1 || port > 65535 {
			o.err = fmt.Errorf("httper: invalid port: %d", port)
			return
		}
		o.port = port
	}
}

// SupportsHTTP2 reports whether target negotiates HTTP/2 ("h2") via TLS ALPN.
//
// target can be either a host[:port] or an https URL.
func SupportsHTTP2(ctx context.Context, target string, opts ...Option) (bool, error) {
	cfg := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.err != nil {
		return false, cfg.err
	}

	host, port, err := parseTLSTarget(target)
	if err != nil {
		return false, err
	}
	if cfg.port != 0 {
		port = strconv.Itoa(cfg.port)
	}
	sniHost := host
	if cfg.host != "" {
		sniHost = cfg.host
	}
	dialHost := host
	if cfg.ip.IsValid() {
		dialHost = cfg.ip.String()
	}

	ctx, cancel := withDefaultTimeout(ctx, cfg.timeout)
	defer cancel()

	d := &net.Dialer{}
	tcpConn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(dialHost, port))
	if err != nil {
		return false, err
	}
	defer tcpConn.Close()

	tlsCfg := &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	if cfg.tlsConfig != nil {
		tlsCfg = cfg.tlsConfig.Clone()
		if len(tlsCfg.NextProtos) == 0 {
			tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		}
	}
	if tlsCfg.ServerName == "" {
		// Go 1.25 requires either ServerName or InsecureSkipVerify.
		// For capability detection we can safely default ServerName to the target host.
		// This also enables proper certificate verification when possible.
		tlsCfg.ServerName = sniHost
	}

	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return false, err
	}
	state := tlsConn.ConnectionState()
	_ = tlsConn.Close()
	return state.NegotiatedProtocol == "h2", nil
}

// SupportsHTTP3 reports whether target advertises HTTP/3 via Alt-Svc.
//
// This does not perform a QUIC handshake; it checks for Alt-Svc entries whose
// protocol starts with "h3".
func SupportsHTTP3(ctx context.Context, target string, opts ...Option) (bool, error) {
	cfg := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.err != nil {
		return false, cfg.err
	}

	u, err := parseHTTPSTargetURL(target)
	if err != nil {
		return false, err
	}

	urlHost := u.Hostname()
	urlPort := u.Port()
	if cfg.host != "" {
		urlHost = cfg.host
	}
	if cfg.port != 0 {
		urlPort = strconv.Itoa(cfg.port)
	}
	u.Host = net.JoinHostPort(urlHost, urlPort)

	ctx, cancel := withDefaultTimeout(ctx, cfg.timeout)
	defer cancel()

	client, cleanup, err := httpClientFor(cfg, urlHost, urlPort)
	if err != nil {
		return false, err
	}
	defer cleanup()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return false, err
	}
	// Ensure Host header matches the (possibly overridden) URL host.
	req.Host = u.Host

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	return hasH3AltSvc(resp.Header), nil
}

func httpClientFor(cfg options, urlHost, urlPort string) (*http.Client, func(), error) {
	var base *http.Transport
	if cfg.httpClient != nil {
		tr, ok := cfg.httpClient.Transport.(*http.Transport)
		if !ok {
			// We need a *http.Transport to safely override TLS/Dial behavior.
			return nil, nil, fmt.Errorf("httper: http client transport must be *http.Transport")
		}
		base = tr
	}

	var tr *http.Transport
	if base != nil {
		tr = base.Clone()
	} else {
		tr = &http.Transport{ForceAttemptHTTP2: true}
	}

	// Apply TLS config.
	if cfg.tlsConfig != nil {
		tr.TLSClientConfig = cfg.tlsConfig.Clone()
	} else if tr.TLSClientConfig != nil {
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	if tr.TLSClientConfig.ServerName == "" {
		tr.TLSClientConfig.ServerName = urlHost
	}

	// Apply dial override when IP is provided.
	if cfg.ip.IsValid() {
		dialAddr := net.JoinHostPort(cfg.ip.String(), urlPort)
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, dialAddr)
		}
	}

	c := &http.Client{Transport: tr}
	return c, tr.CloseIdleConnections, nil
}

func hasH3AltSvc(h http.Header) bool {
	vals := h.Values("Alt-Svc")
	if len(vals) == 0 {
		if v := h.Get("Alt-Svc"); v != "" {
			vals = []string{v}
		}
	}
	for _, v := range vals {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" || strings.EqualFold(part, "clear") {
				continue
			}
			i := strings.IndexByte(part, '=')
			if i <= 0 {
				continue
			}
			proto := strings.TrimSpace(part[:i])
			if strings.HasPrefix(proto, "h3") {
				return true
			}
		}
	}
	return false
}

func withDefaultTimeout(ctx context.Context, d time.Duration) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

func parseTLSTarget(target string) (host, port string, err error) {
	u, err := parseHTTPSTargetURL(target)
	if err == nil {
		return u.Hostname(), u.Port(), nil
	}

	s := strings.TrimSpace(target)
	if s == "" {
		return "", "", fmt.Errorf("httper: empty target")
	}
	host, port, err = net.SplitHostPort(s)
	if err != nil {
		return "", "", fmt.Errorf("httper: invalid target %q: %w", target, err)
	}
	if host == "" {
		return "", "", fmt.Errorf("httper: missing host")
	}
	if port == "" {
		port = "443"
	}
	return host, port, nil
}

func parseHTTPSTargetURL(target string) (*url.URL, error) {
	s := strings.TrimSpace(target)
	if s == "" {
		return nil, fmt.Errorf("httper: empty target")
	}

	var u *url.URL
	var err error
	if strings.Contains(s, "://") {
		u, err = url.Parse(s)
	} else {
		u, err = url.Parse("https://" + s)
	}
	if err != nil {
		return nil, fmt.Errorf("httper: invalid target %q: %w", target, err)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("httper: unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("httper: missing host")
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "443")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}
