package resolver

import (
	"testing"
	"time"

	"github.com/dnsoa/go/assert"
)

func TestNormalizeDomain(t *testing.T) {
	if got := normalizeDomain(" example.com. "); got != "example.com" {
		t.Fatalf("normalizeDomain() = %q", got)
	}
	if got := normalizeDomain(" "); got != "" {
		t.Fatalf("normalizeDomain() = %q", got)
	}
}

func TestWithECSInvalid(t *testing.T) {
	_, err := ResolveA("example.com", WithECS("not-a-prefix"))
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestWithTimeoutInvalid(t *testing.T) {
	_, err := ResolveA("example.com", WithTimeout(0))
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestWithDoHInvalid(t *testing.T) {
	_, err := ResolveA("example.com", WithDoH("not a url"))
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseECSAcceptsSingleIP(t *testing.T) {
	got, err := parseECS([]string{"43.242.1.24", "2001:db8::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(got))
	}
	if got[0].Bits() != 24 {
		t.Fatalf("expected ipv4 /24, got %s", got[0].String())
	}
	if got[1].Bits() != 56 {
		t.Fatalf("expected ipv6 /56, got %s", got[1].String())
	}
}
func TestIPV4(t *testing.T) {
	r := assert.New(t)
	ips, err := ResolveA("www.baidu.com", WithDoT(DotDnspod), WithTimeout(5*time.Second), WithECS("222.246.50.25"))
	r.NoError(err)
	t.Log(ips)
	ips, err = ResolveA("www.baidu.com", WithDoH(DohDnspod), WithECS("42.121.2.24"))
	r.NoError(err)
	t.Log(ips)
	ips, err = ResolveA("www.baidu.com", WithDNSServer("1.1.1.1"), WithECS("222.246.50.25", "42.121.2.24"))
	r.NoError(err)
	t.Log(ips)
	r.True(len(ips) > 0)
}
func TestIPV6(t *testing.T) {
	r := assert.New(t)
	ips, err := ResolveAAAA("www.baidu.com")
	r.NoError(err)
	t.Log(ips)
	r.True(len(ips) > 0)
}
