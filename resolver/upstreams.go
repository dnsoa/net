package resolver

// Common upstreams for convenience.
//
// Notes:
//   - DoT constants use hostnames (not IPs) so TLS SNI/verification works by default.
//   - DNS constants are "ip:53" or "host:53" strings for WithDNSServer/WithTCPServer.
const (
	// DNS (UDP/TCP)
	DNSServerCloudflare1 = "1.1.1.1:53"
	DNSServerCloudflare2 = "1.0.0.1:53"
	DNSServerGoogle1     = "8.8.8.8:53"
	DNSServerGoogle2     = "8.8.4.4:53"
	DNSServerQuad9       = "9.9.9.9:53"

	// DoT (DNS over TLS)
	DoTCloudflare = "cloudflare-dns.com:853"
	DoTGoogle     = "dns.google:853"
	DoTQuad9      = "dns.quad9.net:853"
	DotDnspod     = "dot.pub:853"
	DoT360        = "dot.360.cn:853"

	// DoH (DNS over HTTPS)
	DoHCloudflare = "https://cloudflare-dns.com/dns-query"
	DoHGoogle     = "https://dns.google/dns-query"
	DoHQuad9      = "https://dns.quad9.net/dns-query"
	DoHDnspod     = "https://sm2.doh.pub/dns-query"
	DoH360        = "https://doh.360.cn/dns-query"
)
