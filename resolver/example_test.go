package resolver_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/dnsoa/net/resolver"
)

func Example() {
	// Basic usage — resolve A records via Cloudflare DoH.
	r, err := resolver.New(resolver.DoHCloudflare)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	ips, err := r.LookupNetIP(ctx, "ip4", "www.example.com")
	if err != nil {
		panic(err)
	}
	fmt.Println("A records:", ips)
}

func Example_withECS() {
	// Use ECS for CDN / smart-DNS resolution.
	// Each query randomly picks one prefix from the list,
	// so the authoritative server returns region-aware answers.
	r, err := resolver.New(resolver.DoHDnspod,
		resolver.WithECS(
			"222.246.50.25", // Hunan, China
			"42.121.2.24",   // Shanghai, China
			"116.31.0.0/16", // Guangdong, China
		),
		resolver.WithTimeout(3*time.Second),
	)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	ips, err := r.LookupNetIP(ctx, "ip4", "cdn.example.com")
	if err != nil {
		panic(err)
	}
	fmt.Println("CDN IPs:", ips)
}

func Example_httpTransport() {
	// Use as http.Transport.DialContext so that all HTTP requests
	// in this client go through DoH resolution with ECS.
	r, err := resolver.New(resolver.DoHDnspod,
		resolver.WithECS("222.246.50.25", "42.121.2.24"),
	)
	if err != nil {
		panic(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: r.DialContext,
		},
	}

	resp, err := client.Get("https://www.example.com")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println("Status:", resp.StatusCode)
}

func Example_withDebug() {
	// Enable debug logging to see DNS query details, ECS prefixes used,
	// resolved IPs, and dial connection attempts via slog.
	r, err := resolver.New(resolver.DoHDnspod,
		resolver.WithECS("222.246.50.25", "42.121.2.24"),
		resolver.WithDebug(true),
	)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	ips, err := r.LookupNetIP(ctx, "ip4", "cdn.example.com")
	if err != nil {
		panic(err)
	}
	fmt.Println("IPs:", ips)
}
