package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

// tcpDNSTransportDialer establishes a TCP (or TLS) connection and returns a net.Conn
// that implements DNS-over-TCP framing (2-byte length prefix).
//
// This exists because fastdns's built-in TCPDialer returns a wrapper whose underlying
// Conn is initialized lazily on Write, but fastdns.Client.exchange calls SetDeadline
// before Write, which can panic when Conn is nil.
//
// It implements github.com/phuslu/fastdns.Dialer.
type tcpDNSTransportDialer struct {
	Timeout   time.Duration
	TLSConfig *tls.Config
}

func (d *tcpDNSTransportDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr == "" {
		return nil, fmt.Errorf("resolver: empty upstream addr")
	}

	dialer := &net.Dialer{Timeout: d.Timeout}

	var conn net.Conn
	var err error
	if d.TLSConfig != nil {
		// Use tls.Dialer so the context deadline/cancel is respected.
		td := &tls.Dialer{NetDialer: dialer, Config: d.TLSConfig}
		conn, err = td.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}

	// Apply deadline derived from ctx (preferred) or Timeout (fallback).
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else if d.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(d.Timeout))
	}

	return &tcpDNSConn{Conn: conn}, nil
}

// Put is used by fastdns.Client.exchange to return a connection.
// We don't pool connections here; just close.
func (d *tcpDNSTransportDialer) Put(c net.Conn) {
	_ = c.Close()
}

type tcpDNSConn struct {
	net.Conn
}

func (c *tcpDNSConn) Write(b []byte) (int, error) {
	n := len(b)
	if n > 0xFFFF {
		return 0, fmt.Errorf("resolver: dns message too large: %d", n)
	}

	framed := make([]byte, n+2)
	framed[0] = byte(n >> 8)
	framed[1] = byte(n)
	copy(framed[2:], b)

	_, err := c.Conn.Write(framed)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (c *tcpDNSConn) Read(b []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return 0, err
	}

	msgLen := int(hdr[0])<<8 | int(hdr[1])
	if msgLen == 0 {
		return 0, io.EOF
	}

	if len(b) < msgLen {
		tmp := make([]byte, msgLen)
		if _, err := io.ReadFull(c.Conn, tmp); err != nil {
			return 0, err
		}
		copy(b, tmp[:len(b)])
		return len(b), io.ErrShortBuffer
	}

	if _, err := io.ReadFull(c.Conn, b[:msgLen]); err != nil {
		return 0, err
	}
	return msgLen, nil
}
