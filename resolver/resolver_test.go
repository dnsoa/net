package resolver

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var b [32]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// newTestResolver creates a Resolver with a fake lookupFn (no real DNS).
func newTestResolver(t *testing.T, fn func(ctx context.Context, network, domain string) ([]netip.Addr, error), opts ...Option) *Resolver {
	t.Helper()
	r, err := New(DoHCloudflare, opts...)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	r.lookupFn = fn
	return r
}

// ---------------------------------------------------------------------------
// New — validation
// ---------------------------------------------------------------------------

func TestNewEmptyEndpoint(t *testing.T) {
	_, err := New("")
	if err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}

func TestNewUnsupportedScheme(t *testing.T) {
	_, err := New("ftp://bad")
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestNewInvalidECS(t *testing.T) {
	_, err := New(DoHCloudflare, WithECS("not-a-prefix"))
	if err == nil {
		t.Fatal("expected error for invalid ecs")
	}
}

func TestNewValidEndpoints(t *testing.T) {
	for _, ep := range []string{DoHCloudflare, DoHGoogle, DoHQuad9, DoHDnspod, DoH360} {
		r, err := New(ep)
		if err != nil {
			t.Fatalf("New(%q) error: %v", ep, err)
		}
		if r == nil {
			t.Fatalf("New(%q) returned nil resolver", ep)
		}
	}
}

func TestNewWithHTTP(t *testing.T) {
	_, err := New("http://localhost/dns-query")
	if err != nil {
		t.Fatalf("New with http scheme should work: %v", err)
	}
}

// ---------------------------------------------------------------------------
// normalizeDomain
// ---------------------------------------------------------------------------

func TestNormalizeDomain(t *testing.T) {
	tests := []struct{ in, want string }{
		{" example.com. ", "example.com"},
		{" ", ""},
		{"example.com", "example.com"},
		{"EXAMPLE.COM.", "EXAMPLE.COM"},
		{".", ""},
	}
	for _, tc := range tests {
		if got := normalizeDomain(tc.in); got != tc.want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// parseECS
// ---------------------------------------------------------------------------

func TestParseECSSingleIP(t *testing.T) {
	got, err := parseECS([]string{"43.242.1.24", "2001:db8::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(got))
	}
	if got[0].Bits() != 24 {
		t.Fatalf("expected ipv4 /24, got %s", got[0])
	}
	if got[1].Bits() != 56 {
		t.Fatalf("expected ipv6 /56, got %s", got[1])
	}
}

func TestParseECSCIDR(t *testing.T) {
	got, err := parseECS([]string{"10.0.0.0/8", "fc00::/7"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0].Bits() != 8 {
		t.Fatalf("expected /8, got %s", got[0])
	}
	if got[1].Bits() != 7 {
		t.Fatalf("expected /7, got %s", got[1])
	}
}

func TestParseECSEmpty(t *testing.T) {
	_, err := parseECS([]string{""})
	if err == nil {
		t.Fatal("expected error for empty string prefix")
	}
}

func TestParseECSInvalid(t *testing.T) {
	_, err := parseECS([]string{"not-a-prefix"})
	if err == nil {
		t.Fatal("expected error for invalid prefix")
	}
}

// ---------------------------------------------------------------------------
// uniqueAddrs
// ---------------------------------------------------------------------------

func TestUniqueAddrs(t *testing.T) {
	a := netip.MustParseAddr("1.2.3.4")
	b := netip.MustParseAddr("5.6.7.8")
	got := uniqueAddrs([]netip.Addr{a, b, a, b, a})
	if len(got) != 2 {
		t.Fatalf("expected 2 unique addrs, got %d", len(got))
	}
}

func TestUniqueAddrsNil(t *testing.T) {
	got := uniqueAddrs(nil)
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestUniqueAddrsSingle(t *testing.T) {
	a := netip.MustParseAddr("1.1.1.1")
	got := uniqueAddrs([]netip.Addr{a})
	if len(got) != 1 || got[0] != a {
		t.Fatalf("unexpected: %v", got)
	}
}

// ---------------------------------------------------------------------------
// ipNetworkForDial
// ---------------------------------------------------------------------------

func TestIPNetworkForDial(t *testing.T) {
	tests := []struct{ in, want string }{
		{"tcp", "ip"},
		{"tcp4", "ip4"},
		{"tcp6", "ip6"},
		{"udp", "ip"},
		{"udp4", "ip4"},
		{"udp6", "ip6"},
	}
	for _, tc := range tests {
		if got := ipNetworkForDial(tc.in); got != tc.want {
			t.Errorf("ipNetworkForDial(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// LookupNetIP
// ---------------------------------------------------------------------------

func TestLookupNetIP_IPLiteral(t *testing.T) {
	r, _ := New(DoHCloudflare)
	tests := []struct {
		network, host string
		want          netip.Addr
	}{
		{"ip4", "1.2.3.4", netip.MustParseAddr("1.2.3.4")},
		{"ip6", "::1", netip.MustParseAddr("::1")},
		{"ip", "10.0.0.1", netip.MustParseAddr("10.0.0.1")},
	}
	for _, tc := range tests {
		ips, err := r.LookupNetIP(context.Background(), tc.network, tc.host)
		if err != nil {
			t.Fatalf("LookupNetIP(%q, %q) error: %v", tc.network, tc.host, err)
		}
		if len(ips) != 1 || ips[0] != tc.want {
			t.Fatalf("LookupNetIP(%q, %q) = %v, want [%v]", tc.network, tc.host, ips, tc.want)
		}
	}
}

func TestLookupNetIP_EmptyHost(t *testing.T) {
	r, _ := New(DoHCloudflare)
	_, err := r.LookupNetIP(context.Background(), "ip4", "")
	if !errors.Is(err, ErrEmptyDomain) {
		t.Fatalf("expected ErrEmptyDomain, got %v", err)
	}
}

func TestLookupNetIP_UnsupportedNetwork(t *testing.T) {
	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		return nil, errors.New("should not be called")
	})
	_, err := r.LookupNetIP(context.Background(), "ip5", "example.com")
	if err == nil {
		t.Fatal("expected error for unsupported network")
	}
}

func TestLookupNetIP_IPv4(t *testing.T) {
	want := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")}
	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		if network == "ip4" {
			return want, nil
		}
		return nil, nil
	})

	got, err := r.LookupNetIP(context.Background(), "ip4", "example.com")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(got))
	}
}

func TestLookupNetIP_IPv6(t *testing.T) {
	want := netip.MustParseAddr("2001:db8::1")
	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		if network == "ip6" {
			return []netip.Addr{want}, nil
		}
		return nil, nil
	})

	got, err := r.LookupNetIP(context.Background(), "ip6", "example.com")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("expected [%v], got %v", want, got)
	}
}

func TestLookupNetIP_DualStack_IPv6First(t *testing.T) {
	v4 := netip.MustParseAddr("1.2.3.4")
	v6 := netip.MustParseAddr("2001:db8::1")

	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		switch network {
		case "ip4":
			return []netip.Addr{v4}, nil
		case "ip6":
			return []netip.Addr{v6}, nil
		}
		return nil, nil
	})

	got, err := r.LookupNetIP(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 IPs, got %v", got)
	}
	// IPv6 must come before IPv4.
	if got[0] != v6 {
		t.Fatalf("expected IPv6 first, got %v", got)
	}
	if got[1] != v4 {
		t.Fatalf("expected IPv4 second, got %v", got)
	}
}

func TestLookupNetIP_DualStack_V6OnlyFails(t *testing.T) {
	v4 := netip.MustParseAddr("1.2.3.4")

	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		if network == "ip4" {
			return []netip.Addr{v4}, nil
		}
		return nil, errors.New("no AAAA")
	})

	got, err := r.LookupNetIP(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("should succeed with v4: %v", err)
	}
	if len(got) != 1 || got[0] != v4 {
		t.Fatalf("expected [%v], got %v", v4, got)
	}
}

func TestLookupNetIP_DualStack_BothFail(t *testing.T) {
	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		return nil, errors.New("fail " + network)
	})

	_, err := r.LookupNetIP(context.Background(), "ip", "example.com")
	if err == nil {
		t.Fatal("expected error when both families fail")
	}
}

// ---------------------------------------------------------------------------
// LookupHost
// ---------------------------------------------------------------------------

func TestLookupHost(t *testing.T) {
	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		if network == "ip4" {
			return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
		}
		return nil, nil
	})

	hosts, err := r.LookupHost(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(hosts) == 0 {
		t.Fatal("expected at least one host")
	}
	if hosts[0] != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %s", hosts[0])
	}
}

// ---------------------------------------------------------------------------
// ECS random selection
// ---------------------------------------------------------------------------

func TestECSRandomSelection(t *testing.T) {
	ecsList := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	r, err := New(DoHCloudflare, WithECS(ecsList...))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Verify all configured prefixes.
	if len(r.cfg.ecs) != 3 {
		t.Fatalf("expected 3 ECS prefixes, got %d", len(r.cfg.ecs))
	}

	// Call randomECS many times and verify all prefixes are eventually chosen.
	seen := make(map[netip.Prefix]int)
	for i := 0; i < 300; i++ {
		p := r.randomECS()
		seen[p]++
	}
	for _, prefix := range r.cfg.ecs {
		if seen[prefix] == 0 {
			t.Fatalf("ECS prefix %s was never chosen in 300 iterations", prefix)
		}
	}
}

// ---------------------------------------------------------------------------
// shuffledCopy
// ---------------------------------------------------------------------------

func TestShuffledCopy_ReturnsNewSlice(t *testing.T) {
	r, _ := New(DoHCloudflare)
	in := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")}
	out := r.shuffledCopy(in)
	if &in[0] == &out[0] {
		t.Fatal("shuffledCopy should return a new slice")
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(out))
	}
}

func TestShuffledCopy_SingleElement(t *testing.T) {
	r, _ := New(DoHCloudflare)
	in := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	out := r.shuffledCopy(in)
	if len(out) != 1 || out[0] != in[0] {
		t.Fatalf("unexpected: %v", out)
	}
}

func TestShuffledCopy_Nil(t *testing.T) {
	r, _ := New(DoHCloudflare)
	out := r.shuffledCopy(nil)
	if len(out) != 0 {
		t.Fatalf("expected empty, got %v", out)
	}
}

func TestShuffledCopy_Randomizes(t *testing.T) {
	r, _ := New(DoHCloudflare)
	// Use a deterministic RNG and verify the output differs from input order.
	r.rngMu.Lock()
	r.rng = rand.New(rand.NewPCG(42, 99))
	r.rngMu.Unlock()

	in := []netip.Addr{
		netip.MustParseAddr("1.0.0.1"),
		netip.MustParseAddr("1.0.0.2"),
		netip.MustParseAddr("1.0.0.3"),
		netip.MustParseAddr("1.0.0.4"),
		netip.MustParseAddr("1.0.0.5"),
	}

	diffSeen := false
	for i := 0; i < 20; i++ {
		out := r.shuffledCopy(in)
		for j := range in {
			if out[j] != in[j] {
				diffSeen = true
				break
			}
		}
		if diffSeen {
			break
		}
	}
	if !diffSeen {
		t.Fatal("shuffledCopy never produced a different order in 20 attempts")
	}
}

// ---------------------------------------------------------------------------
// DialContext — IP literal (no DNS)
// ---------------------------------------------------------------------------

func TestDialContext_IPLiteral(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, _ := ln.Accept()
		if c != nil {
			_ = c.Close()
		}
	}()

	r, _ := New(DoHCloudflare)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := r.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext error: %v", err)
	}
	_ = conn.Close()
}

// ---------------------------------------------------------------------------
// DialContext — with hostname via mock lookup
// ---------------------------------------------------------------------------

func TestDialContext_Hostname(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := itoa(ln.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		if network == "ip4" {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return nil, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := r.DialContext(ctx, "tcp4", net.JoinHostPort("example.com", port))
	if err != nil {
		t.Fatalf("DialContext error: %v", err)
	}
	_ = conn.Close()
}

// ---------------------------------------------------------------------------
// DialContext — dual-stack prefers IPv6, falls back to IPv4
// ---------------------------------------------------------------------------

func TestDialContext_DualStack_PrefersIPv6(t *testing.T) {
	// Listen on IPv6 loopback.
	ln6, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("ipv6 not available: %v", err)
	}
	defer ln6.Close()
	port := itoa(ln6.Addr().(*net.TCPAddr).Port)

	go func() {
		c, _ := ln6.Accept()
		if c != nil {
			_ = c.Close()
		}
	}()

	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		switch network {
		case "ip6":
			return []netip.Addr{netip.MustParseAddr("::1")}, nil
		case "ip4":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return nil, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := r.DialContext(ctx, "tcp", net.JoinHostPort("example.com", port))
	if err != nil {
		t.Fatalf("DialContext error: %v", err)
	}
	// Should have connected to ::1.
	remote := conn.RemoteAddr().(*net.TCPAddr)
	if !remote.IP.Equal(net.ParseIP("::1")) {
		t.Fatalf("expected connection to ::1, got %v", remote.IP)
	}
	_ = conn.Close()
}

func TestDialContext_DualStack_FallbackToV4(t *testing.T) {
	ln4, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln4.Close()
	port := itoa(ln4.Addr().(*net.TCPAddr).Port)

	go func() {
		c, _ := ln4.Accept()
		if c != nil {
			_ = c.Close()
		}
	}()

	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		switch network {
		case "ip6":
			// Return an unreachable v6 address to force fallback.
			return []netip.Addr{netip.MustParseAddr("::2")}, nil
		case "ip4":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return nil, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := r.DialContext(ctx, "tcp", net.JoinHostPort("example.com", port))
	if err != nil {
		t.Fatalf("DialContext error: %v", err)
	}
	remote := conn.RemoteAddr().(*net.TCPAddr)
	if !remote.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("expected fallback to 127.0.0.1, got %v", remote.IP)
	}
	_ = conn.Close()
}

func TestDialContext_EmptyHost(t *testing.T) {
	r, _ := New(DoHCloudflare)
	_, err := r.DialContext(context.Background(), "tcp", ":80")
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestDialContext_NoIPs(t *testing.T) {
	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		return nil, errors.New("nxdomain")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := r.DialContext(ctx, "tcp4", "nxdomain.example.com:80")
	if err == nil {
		t.Fatal("expected error when lookup fails")
	}
}

// ---------------------------------------------------------------------------
// DialContext — randomises candidate order
// ---------------------------------------------------------------------------

func TestDialContext_RandomizesCandidates(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen1: %v", err)
	}
	defer ln1.Close()

	addr1 := ln1.Addr().(*net.TCPAddr)
	ln2, err := net.Listen("tcp", net.JoinHostPort("127.0.0.2", itoa(addr1.Port)))
	if err != nil {
		t.Skipf("listen2 failed (%v), skipping", err)
		return
	}
	defer ln2.Close()

	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		if network == "ip4" {
			return []netip.Addr{
				netip.MustParseAddr("127.0.0.1"),
				netip.MustParseAddr("127.0.0.2"),
			}, nil
		}
		return nil, nil
	})

	// Deterministic shuffle.
	r.rngMu.Lock()
	r.rng = rand.New(rand.NewPCG(1, 2))
	r.rngMu.Unlock()

	acceptCh := make(chan string, 50)
	stopAccept := make(chan struct{})
	accept := func(ln net.Listener, tag string) {
		for {
			_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(200 * time.Millisecond))
			c, err := ln.Accept()
			select {
			case <-stopAccept:
				return
			default:
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			_ = c.Close()
			acceptCh <- tag
		}
	}
	go accept(ln1, "127.0.0.1")
	go accept(ln2, "127.0.0.2")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	port := itoa(addr1.Port)
	for i := 0; i < 20; i++ {
		c, err := r.DialContext(ctx, "tcp4", net.JoinHostPort("example.com", port))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_ = c.Close()
	}

	close(stopAccept)

	count1, count2 := 0, 0
	deadline := time.After(1 * time.Second)
collect:
	for count1+count2 < 20 {
		select {
		case tag := <-acceptCh:
			if tag == "127.0.0.1" {
				count1++
			} else {
				count2++
			}
		case <-deadline:
			break collect
		}
	}
	if count1 == 0 || count2 == 0 {
		t.Fatalf("expected both listeners to receive connections, got count1=%d count2=%d", count1, count2)
	}
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

func TestWithTimeout(t *testing.T) {
	r, err := New(DoHCloudflare, WithTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if r.cfg.timeout != 10*time.Second {
		t.Fatalf("expected 10s, got %v", r.cfg.timeout)
	}
}

func TestWithTimeout_Invalid(t *testing.T) {
	r, err := New(DoHCloudflare, WithTimeout(-1))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Should keep default.
	if r.cfg.timeout != 5*time.Second {
		t.Fatalf("expected default 5s, got %v", r.cfg.timeout)
	}
}

func TestWithECS_Empty(t *testing.T) {
	r, err := New(DoHCloudflare, WithECS())
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(r.cfg.ecs) != 0 {
		t.Fatalf("expected empty ecs, got %v", r.cfg.ecs)
	}
}

func TestWithECS_Valid(t *testing.T) {
	r, err := New(DoHCloudflare, WithECS("1.2.3.0/24", "10.0.0.1"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(r.cfg.ecs) != 2 {
		t.Fatalf("expected 2, got %d", len(r.cfg.ecs))
	}
}

func TestWithHTTPTransport_Nil(t *testing.T) {
	r, err := New(DoHCloudflare, WithHTTPTransport(nil))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if r.cfg.httpTransport != nil {
		t.Fatal("expected nil transport")
	}
}

// ---------------------------------------------------------------------------
// Concurrency safety
// ---------------------------------------------------------------------------

func TestLookupNetIP_Concurrent(t *testing.T) {
	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		// Simulate slight latency.
		time.Sleep(1 * time.Millisecond)
		if network == "ip4" {
			return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("::1")}, nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.LookupNetIP(context.Background(), "ip", "example.com")
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// WithDebug option
// ---------------------------------------------------------------------------

func TestWithDebugEnable(t *testing.T) {
	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
	}, WithDebug(true))
	if !r.cfg.debug {
		t.Fatal("expected debug to be true")
	}
}

func TestWithDebugDisable(t *testing.T) {
	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
	}, WithDebug(false))
	if r.cfg.debug {
		t.Fatal("expected debug to be false")
	}
}

func TestWithDebugDefaultOff(t *testing.T) {
	r := newTestResolver(t, func(ctx context.Context, network, domain string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
	})
	if r.cfg.debug {
		t.Fatal("expected debug to be false by default")
	}
}
