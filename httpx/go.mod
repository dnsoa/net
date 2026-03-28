module github.com/dnsoa/net/httpx

go 1.25.6

require (
	github.com/dnsoa/go/allocator v0.0.0
	github.com/dnsoa/go/sync v0.0.0
	golang.org/x/net v0.52.0
)

replace (
	github.com/dnsoa/go/allocator => ../../go/allocator
	github.com/dnsoa/go/sync => ../../go/sync
)
