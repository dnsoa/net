package pinger

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakePinger struct {
	delay time.Duration

	rtts map[netip.Addr]time.Duration
	errs map[netip.Addr]error

	callsMu sync.Mutex
	calls   []netip.Addr

	inflight int64
	maxSeen  int64
}

func (f *fakePinger) Ping(ctx context.Context, addr netip.Addr) (time.Duration, error) {
	f.callsMu.Lock()
	f.calls = append(f.calls, addr)
	f.callsMu.Unlock()

	cur := atomic.AddInt64(&f.inflight, 1)
	for {
		old := atomic.LoadInt64(&f.maxSeen)
		if cur <= old {
			break
		}
		if atomic.CompareAndSwapInt64(&f.maxSeen, old, cur) {
			break
		}
	}
	defer atomic.AddInt64(&f.inflight, -1)

	if f.delay > 0 {
		t := time.NewTimer(f.delay)
		defer func() {
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
		}()
		select {
		case <-t.C:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}

	if f.errs != nil {
		if err, ok := f.errs[addr]; ok {
			return 0, err
		}
	}
	if f.rtts != nil {
		if rtt, ok := f.rtts[addr]; ok {
			return rtt, nil
		}
	}
	return 0, nil
}

func TestPingAllWith_OrderAndInvalid(t *testing.T) {
	p := &fakePinger{rtts: map[netip.Addr]time.Duration{}}

	a := netip.MustParseAddr("1.1.1.1")
	b := netip.Addr{} // invalid
	c := netip.MustParseAddr("8.8.8.8")
	p.rtts[a] = 12 * time.Millisecond
	p.rtts[c] = 34 * time.Millisecond

	res, err := PingAllWith(context.Background(), p, []netip.Addr{a, b, c}, WithConcurrency(2), WithTimeout(100*time.Millisecond))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 3 {
		t.Fatalf("unexpected result len: %d", len(res))
	}
	if res[0].Addr != a || res[0].RTT != 12*time.Millisecond || res[0].Err != nil {
		t.Fatalf("unexpected res[0]: %+v", res[0])
	}
	if res[1].Addr.IsValid() {
		t.Fatalf("expected res[1] invalid addr")
	}
	if !errors.Is(res[1].Err, ErrInvalidAddr) {
		t.Fatalf("expected ErrInvalidAddr, got: %v", res[1].Err)
	}
	if res[2].Addr != c || res[2].RTT != 34*time.Millisecond || res[2].Err != nil {
		t.Fatalf("unexpected res[2]: %+v", res[2])
	}

	p.callsMu.Lock()
	defer p.callsMu.Unlock()
	if len(p.calls) != 2 {
		t.Fatalf("expected 2 Ping calls (invalid skipped), got %d", len(p.calls))
	}
}

func TestPingAllWith_Timeout(t *testing.T) {
	p := &fakePinger{delay: 50 * time.Millisecond}
	addr := netip.MustParseAddr("1.1.1.1")

	res, err := PingAllWith(context.Background(), p, []netip.Addr{addr}, WithTimeout(5*time.Millisecond))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("unexpected result len: %d", len(res))
	}
	if !errors.Is(res[0].Err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got: %v", res[0].Err)
	}
}

func TestPingAllWith_ConcurrencyLimit(t *testing.T) {
	p := &fakePinger{delay: 25 * time.Millisecond}
	addrs := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.1.1.2"),
		netip.MustParseAddr("1.1.1.3"),
		netip.MustParseAddr("1.1.1.4"),
		netip.MustParseAddr("1.1.1.5"),
	}

	_, err := PingAllWith(context.Background(), p, addrs, WithConcurrency(2), WithTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if max := atomic.LoadInt64(&p.maxSeen); max > 2 {
		t.Fatalf("expected max inflight <= 2, got %d", max)
	}
}

func TestPingAll_ICMPInvalidPayloadSize(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := PingAllWith(ctx, NewICMPPinger(), []netip.Addr{netip.MustParseAddr("127.0.0.1")}, WithPayloadSize(2000))
	if err == nil {
		t.Fatalf("expected error")
	}
}
