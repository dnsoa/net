package pinger

import (
	"context"
	"net/netip"
	"sync"
)

type pingJob struct {
	idx  int
	addr netip.Addr
}

func pingGroup(ctx context.Context, p Pinger, addrs []netip.Addr, cfg options) ([]Result, error) {
	results := make([]Result, len(addrs))

	workers := cfg.concurrency
	if workers > len(addrs) {
		workers = len(addrs)
	}

	jobs := make(chan pingJob)
	var wg sync.WaitGroup

	for range workers {
		wg.Go(func() {
			for job := range jobs {
				addr := job.addr
				res := Result{Addr: addr}
				if !addr.IsValid() {
					res.Err = ErrInvalidAddr
					results[job.idx] = res
					continue
				}
				pctx, cancel := context.WithTimeout(ctx, cfg.timeout)
				rtt, err := p.Ping(pctx, addr)
				cancel()
				res.RTT = rtt
				res.Err = err
				results[job.idx] = res
			}
		})
	}

	for i, addr := range addrs {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		case jobs <- pingJob{idx: i, addr: addr}:
		}
	}
	close(jobs)
	wg.Wait()

	return results, nil
}
