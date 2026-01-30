package pinger

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestPingAllTCP_Success(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi: %v", err)
	}

	accepted := make(chan struct{}, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr == nil {
			_ = c.Close()
			accepted <- struct{}{}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	res, err := PingAllTCP(
		ctx,
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")},
		port,
		WithTimeout(200*time.Millisecond),
		WithPayloadSize(2000),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("unexpected result len: %d", len(res))
	}
	if res[0].Err != nil {
		t.Fatalf("unexpected ping error: %v", res[0].Err)
	}
	select {
	case <-accepted:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("server did not accept connection")
	}
}

func TestPingAllTCP_ClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	res, err := PingAllTCP(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, port, WithTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("unexpected result len: %d", len(res))
	}
	if res[0].Err == nil {
		t.Fatalf("expected connect error")
	}
}

func TestPingAllTCP_InvalidPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	res, err := PingAllTCP(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, 0, WithTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("unexpected result len: %d", len(res))
	}
	if res[0].Err == nil {
		t.Fatalf("expected per-result error")
	}
}

func TestPingAllTCPTargets_MultiPorts(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen1: %v", err)
	}
	defer ln1.Close()
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen2: %v", err)
	}
	defer ln2.Close()

	_, p1s, err := net.SplitHostPort(ln1.Addr().String())
	if err != nil {
		t.Fatalf("split1: %v", err)
	}
	_, p2s, err := net.SplitHostPort(ln2.Addr().String())
	if err != nil {
		t.Fatalf("split2: %v", err)
	}
	p1, _ := strconv.Atoi(p1s)
	p2, _ := strconv.Atoi(p2s)

	go func() { c, _ := ln1.Accept(); if c != nil { _ = c.Close() } }()
	go func() { c, _ := ln2.Accept(); if c != nil { _ = c.Close() } }()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	addr := netip.MustParseAddr("127.0.0.1")
	targets := []TCPTarget{{Addr: addr, Port: p1}, {Addr: addr, Port: p2}}
	res, err := PingAllTCPTargets(ctx, targets, WithTimeout(300*time.Millisecond), WithConcurrency(2))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("unexpected result len: %d", len(res))
	}
	if res[0].Addr != addr || res[0].Port != p1 || res[0].Err != nil {
		t.Fatalf("unexpected res[0]: %+v", res[0])
	}
	if res[1].Addr != addr || res[1].Port != p2 || res[1].Err != nil {
		t.Fatalf("unexpected res[1]: %+v", res[1])
	}
}

func TestParseTCPTargets(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		wantLen int
		wantErr bool
	}{
		{name: "ipv4", in: []string{"127.0.0.1:80"}, wantLen: 1},
		{name: "ipv6", in: []string{"[::1]:443"}, wantLen: 1},
		{name: "missing_port", in: []string{"127.0.0.1"}, wantErr: true},
		{name: "bad_ip", in: []string{"not-an-ip:80"}, wantErr: true},
		{name: "bad_ipv6_no_brackets", in: []string{"::1:443"}, wantErr: true},
		{name: "bad_port", in: []string{"127.0.0.1:0"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTCPTargets(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if err == nil && len(got) != tt.wantLen {
				t.Fatalf("len=%d want=%d", len(got), tt.wantLen)
			}
		})
	}
}
