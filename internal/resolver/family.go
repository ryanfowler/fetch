package resolver

import (
	"context"
	"errors"
	"net"
	"time"
)

// addressFamily identifies the address family returned by one DNS query.
// Keeping this separate from net.IP lets resolution preserve the resolver's
// preference before the dialer interleaves candidates.
type addressFamily uint8

const (
	familyUnknown addressFamily = iota
	familyIPv4
	familyIPv6
)

const addressFamilyGrace = 100 * time.Millisecond

type familyResult struct {
	family addressFamily
	addrs  []net.IPAddr
	err    error
}

// resolveAddressFamilies runs the two independent address queries together.
// The first family that produces a usable address is preferred. The other
// query gets a short grace period so dual-stack answers are retained, but a
// stalled family cannot hold up a usable result until the request deadline.
func resolveAddressFamilies(ctx context.Context, lookup func(context.Context, uint16) ([]net.IPAddr, error)) ([]net.IPAddr, error) {
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan familyResult, 2)
	for _, query := range []struct {
		family addressFamily
		typ    uint16
	}{
		{family: familyIPv4, typ: dnsTypeA},
		{family: familyIPv6, typ: dnsTypeAAAA},
	} {
		query := query
		go func() {
			addrs, err := lookup(queryCtx, query.typ)
			results <- familyResult{family: query.family, addrs: deduplicateAddresses(addrs), err: err}
		}()
	}

	var preferred, secondary []net.IPAddr
	var preferredFamily addressFamily
	var firstErr error
	completed := 0
	var grace <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for completed < 2 {
		select {
		case result := <-results:
			completed++
			if len(result.addrs) == 0 {
				if result.err != nil && firstErr == nil && !errors.Is(result.err, context.Canceled) {
					firstErr = result.err
				}
				continue
			}

			if preferredFamily == familyUnknown {
				preferredFamily = result.family
				preferred = result.addrs
				timer = time.NewTimer(addressFamilyGrace)
				grace = timer.C
			} else {
				secondary = result.addrs
				cancel()
				return appendAddressLists(preferred, secondary), nil
			}
		case <-grace:
			cancel()
			return preferred, nil
		case <-ctx.Done():
			// A usable answer is still valid when cancellation races with the
			// grace period. Otherwise preserve the caller's cancellation error.
			if preferredFamily != familyUnknown {
				cancel()
				return appendAddressLists(preferred, secondary), nil
			}
			cancel()
			return nil, ctx.Err()
		}
	}

	if preferredFamily != familyUnknown {
		return appendAddressLists(preferred, secondary), nil
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, errors.New("no such host")
}

func deduplicateAddresses(addrs []net.IPAddr) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}
		// String canonicalizes the 4-byte and 16-byte forms of an IPv4
		// address. Include Zone because it is part of an IPAddr's identity.
		key := addr.IP.String() + "\x00" + addr.Zone
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		addr.IP = append(net.IP(nil), addr.IP...)
		out = append(out, addr)
	}
	return out
}

func appendAddressLists(first, second []net.IPAddr) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(first)+len(second))
	seen := make(map[string]struct{}, len(first)+len(second))
	for _, list := range [][]net.IPAddr{first, second} {
		for _, addr := range list {
			key := addr.IP.String() + "\x00" + addr.Zone
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, addr)
		}
	}
	return out
}

// interleaveAddressFamilies produces Happy-Eyeballs candidates. The first
// address family remains first, and each family's original order is retained.
func interleaveAddressFamilies(addrs []net.IPAddr) []net.IPAddr {
	if len(addrs) < 2 {
		return append([]net.IPAddr(nil), addrs...)
	}
	firstFamily := ipAddressFamily(addrs[0].IP)
	if firstFamily == familyUnknown {
		return append([]net.IPAddr(nil), addrs...)
	}
	first := make([]net.IPAddr, 0, len(addrs))
	second := make([]net.IPAddr, 0, len(addrs))
	for _, addr := range addrs {
		if ipAddressFamily(addr.IP) == firstFamily {
			first = append(first, addr)
		} else {
			second = append(second, addr)
		}
	}
	if len(second) == 0 {
		return first
	}
	out := make([]net.IPAddr, 0, len(addrs))
	for i := 0; i < len(first) || i < len(second); i++ {
		if i < len(first) {
			out = append(out, first[i])
		}
		if i < len(second) {
			out = append(out, second[i])
		}
	}
	return out
}

func ipAddressFamily(ip net.IP) addressFamily {
	if ip.To4() != nil {
		return familyIPv4
	}
	if ip.To16() != nil {
		return familyIPv6
	}
	return familyUnknown
}
