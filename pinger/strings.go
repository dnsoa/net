package pinger

import (
	"context"
	"fmt"
	"net/netip"
)

// PingAllStrings parses each string as an IP and pings each one once.
//
// Invalid IP strings will produce a Result with Err set.
func PingAllStrings(ctx context.Context, ips []string, opts ...Option) ([]Result, error) {
	parseErrs := make([]error, len(ips))
	addrs := make([]netip.Addr, len(ips))
	for i, s := range ips {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			parseErrs[i] = fmt.Errorf("pinger: invalid ip %q: %w", s, err)
			addrs[i] = netip.Addr{}
			continue
		}
		addrs[i] = ip
	}
	res, err := PingAll(ctx, addrs, opts...)
	if err != nil {
		return nil, err
	}
	for i, perr := range parseErrs {
		if perr != nil {
			res[i].Err = perr
		}
	}
	return res, nil
}
