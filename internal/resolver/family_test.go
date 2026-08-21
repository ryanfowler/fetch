package resolver

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"
)

func TestResolveAddressFamiliesPrefersFirstUsableFamily(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	startedAt := time.Now()
	addrs, err := resolveAddressFamilies(ctx, func(ctx context.Context, typ uint16) ([]net.IPAddr, error) {
		if typ == dnsTypeA {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return nil, ctx.Err()
		}
		<-started
		return []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(startedAt); elapsed >= 500*time.Millisecond {
		t.Fatalf("resolution took %s; usable family should not wait for the full request timeout", elapsed)
	}
	if got := ipStrings(addrs); !slices.Equal(got, []string{"2001:db8::1"}) {
		t.Fatalf("addresses = %v, want IPv6 result", got)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("stalled family was not canceled")
	}
}

func TestResolveAddressFamiliesKeepsOrderAndDeduplicates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrs, err := resolveAddressFamilies(ctx, func(_ context.Context, typ uint16) ([]net.IPAddr, error) {
		if typ == dnsTypeA {
			return []net.IPAddr{
				{IP: net.ParseIP("192.0.2.1")},
				{IP: net.ParseIP("192.0.2.1")},
				{IP: net.ParseIP("192.0.2.2")},
			}, nil
		}
		return []net.IPAddr{
			{IP: net.ParseIP("2001:db8::1")},
			{IP: net.ParseIP("2001:db8::1")},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Both queries are immediate, so either response can win the race. The
	// winning family must remain first and each family's source order must be
	// stable after exact duplicates are removed.
	if len(addrs) != 3 {
		t.Fatalf("addresses = %v, want three unique addresses", ipStrings(addrs))
	}
	firstFamily := ipAddressFamily(addrs[0].IP)
	if firstFamily != familyIPv4 && firstFamily != familyIPv6 {
		t.Fatalf("first address has unknown family: %v", addrs[0])
	}
	if firstFamily == familyIPv4 {
		if got := ipStrings(addrs); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2", "2001:db8::1"}) {
			t.Fatalf("addresses = %v, want IPv4-first order", got)
		}
	} else if got := ipStrings(addrs); !slices.Equal(got, []string{"2001:db8::1", "192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("addresses = %v, want IPv6-first order", got)
	}
}

func TestResolverSystemLookupDeduplicatesAndInterleavesCandidates(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("2001:db8::1")},
			{IP: net.ParseIP("2001:db8::1")},
			{IP: net.ParseIP("192.0.2.1")},
			{IP: net.ParseIP("2001:db8::2")},
		}, nil
	}
	resolver := New(Config{SystemLookupIPAddr: lookup})
	addrs, err := resolver.LookupIPAddr(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := ipStrings(addrs); !slices.Equal(got, []string{"2001:db8::1", "192.0.2.1", "2001:db8::2"}) {
		t.Fatalf("resolved addresses = %v", got)
	}
	endpoint, err := resolver.ResolveAddress(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if got := ipStrings(endpoint.Addrs); !slices.Equal(got, []string{"2001:db8::1", "192.0.2.1", "2001:db8::2"}) {
		t.Fatalf("dial candidates = %v, want interleaved family order", got)
	}
}
