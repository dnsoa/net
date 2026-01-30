package pinger

import (
	"context"
	crand "crypto/rand"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	ErrInvalidAddr = errors.New("pinger: invalid addr")
)

type icmpPinger struct {
	id          int
	payloadSize int
}

// NewICMPPinger returns a Pinger that sends ICMP echo requests.
//
// Note: On many systems this may require elevated privileges, or OS-level
// configuration for unprivileged ICMP sockets.
func NewICMPPinger() Pinger {
	return &icmpPinger{id: os.Getpid() & 0xffff, payloadSize: 32}
}

func (p *icmpPinger) Ping(ctx context.Context, addr netip.Addr) (time.Duration, error) {
	if !addr.IsValid() {
		return 0, ErrInvalidAddr
	}
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(1 * time.Second)
	}

	seq := rand.IntN(1<<15) + 1
	ps := p.payloadSize
	if ps < 0 {
		ps = 0
	}
	payload := make([]byte, ps)
	if len(payload) > 0 {
		_, _ = crand.Read(payload)
	}

	if addr.Is4() {
		return pingICMP(ctx, "0.0.0.0", "ip4:icmp", "udp4", 1, ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply, addr, p.id, seq, payload, deadline)
	}
	return pingICMP(ctx, "::", "ip6:ipv6-icmp", "udp6", 58, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, addr, p.id, seq, payload, deadline)
}

func pingICMP(
	ctx context.Context,
	bindAddr string,
	primaryNetwork string,
	fallbackNetwork string,
	proto int,
	reqType icmp.Type,
	replyType icmp.Type,
	addr netip.Addr,
	id int,
	seq int,
	payload []byte,
	deadline time.Time,
) (time.Duration, error) {
	c, err := icmp.ListenPacket(primaryNetwork, bindAddr)
	if err != nil {
		c, err = icmp.ListenPacket(fallbackNetwork, bindAddr)
		if err != nil {
			return 0, err
		}
	}
	defer c.Close()

	_ = c.SetDeadline(deadline)

	m := icmp.Message{
		Type: reqType,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: payload},
	}
	b, err := m.Marshal(nil)
	if err != nil {
		return 0, err
	}

	dst := &net.IPAddr{IP: addr.AsSlice()}
	start := time.Now()
	if _, err := c.WriteTo(b, dst); err != nil {
		return 0, err
	}

	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}

		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		rm, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		if rm.Type != replyType {
			continue
		}
		echo, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if echo.ID != id || echo.Seq != seq {
			continue
		}
		return time.Since(start), nil
	}
}
