package resolver

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestResolveHTTPSFollowsAliasesAndUsesServiceTarget(t *testing.T) {
	queries := make([]string, 0, 4)
	owner := func(value string) Name {
		name, err := ParseName(value)
		if err != nil {
			t.Fatal(err)
		}
		return name
	}
	aliasOwner := owner("example.com")
	aliasTarget := owner("alias.example.com")
	answers := map[string][]Record{
		"example.com.":       {{Owner: aliasOwner, Type: dnsTypeHTTPS, Class: 1, TTL: 30, TTLPresent: true, RData: svcbRData(0, []string{"alias", "example", "com"})}},
		"alias.example.com.": {{Owner: aliasTarget, Type: dnsTypeHTTPS, Class: 1, TTL: 20, TTLPresent: true, RData: svcbRData(1, []string{"edge", "example", "net"}, svcbParam(svcParamPort, []byte{0x1f, 0x90}), svcbParam(svcParamIPv4Hint, []byte{192, 0, 2, 1}))}},
	}
	addressCalls := make([]string, 0, 2)
	result, err := ResolveHTTPS(context.Background(), "example.com", func(_ context.Context, name string) ([]Record, error) {
		queries = append(queries, name)
		return answers[name], nil
	}, func(_ context.Context, name string) ([]net.IPAddr, error) {
		addressCalls = append(addressCalls, name)
		return []net.IPAddr{{IP: net.ParseIP("198.51.100.7")}}, nil
	}, ServiceDiscoveryOptions{RandomInt: func(int) int { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(queries, ","), "example.com.,alias.example.com."; got != want {
		t.Fatalf("HTTPS queries = %q, want %q", got, want)
	}
	if len(addressCalls) != 1 || addressCalls[0] != "edge.example.net." {
		t.Fatalf("address queries = %v, want only service target", addressCalls)
	}
	if result.EffectiveTarget.String() != "alias.example.com." || len(result.Candidates) != 1 {
		t.Fatalf("discovery = %#v", result)
	}
	candidate := result.Candidates[0]
	if candidate.TargetName.String() != "edge.example.net." || candidate.Port != 8080 {
		t.Fatalf("candidate target/port = %s/%d", candidate.TargetName, candidate.Port)
	}
	if len(candidate.Addresses) != 2 || candidate.Addresses[0].IP.String() != "192.0.2.1" || candidate.Addresses[1].IP.String() != "198.51.100.7" {
		t.Fatalf("candidate addresses = %v", candidate.Addresses)
	}
	if result.TTL != 20 || !result.TTLPresent || candidate.TTL != 20 {
		t.Fatalf("TTL = result %d/%v candidate %d", result.TTL, result.TTLPresent, candidate.TTL)
	}
}

func TestResolveHTTPSAliasLoopFallsBackToOrigin(t *testing.T) {
	one, _ := ParseName("one.example")
	two, _ := ParseName("two.example")
	answers := map[string][]Record{
		"one.example.": {{Owner: one, Type: dnsTypeHTTPS, Class: 1, RData: svcbRData(0, []string{"two", "example"})}},
		"two.example.": {{Owner: two, Type: dnsTypeHTTPS, Class: 1, RData: svcbRData(0, []string{"one", "example"})}},
	}
	result, err := ResolveHTTPS(context.Background(), "one.example", func(_ context.Context, name string) ([]Record, error) {
		return answers[name], nil
	}, nil, ServiceDiscoveryOptions{})
	if err != nil || len(result.Candidates) != 0 || result.EffectiveTarget.String() != "one.example." {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
}

func TestResolveHTTPSRootTargets(t *testing.T) {
	origin, _ := ParseName("origin.example")
	serviceOwner, _ := ParseName("service.example")
	answers := map[string][]Record{
		"origin.example.":  {{Owner: origin, Type: dnsTypeHTTPS, Class: 1, RData: svcbRData(0, []string{"service", "example"})}},
		"service.example.": {{Owner: serviceOwner, Type: dnsTypeHTTPS, Class: 1, RData: svcbRData(1, nil)}},
	}
	var lookedUp string
	result, err := ResolveHTTPS(context.Background(), "origin.example", func(_ context.Context, name string) ([]Record, error) {
		return answers[name], nil
	}, func(_ context.Context, name string) ([]net.IPAddr, error) {
		lookedUp = name
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.4")}}, nil
	}, ServiceDiscoveryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if lookedUp != "service.example." || result.Candidates[0].TargetName.String() != lookedUp {
		t.Fatalf("lookup target = %q, candidate = %s", lookedUp, result.Candidates[0].TargetName)
	}

	unavailable := []Record{{Owner: origin, Type: dnsTypeHTTPS, Class: 1, RData: svcbRData(0, nil)}}
	result, err = ResolveHTTPS(context.Background(), "origin.example", func(context.Context, string) ([]Record, error) {
		return unavailable, nil
	}, nil, ServiceDiscoveryOptions{})
	if err != nil || len(result.Candidates) != 0 {
		t.Fatalf("root AliasMode result = %#v, err = %v", result, err)
	}
}

func TestResolveHTTPSDelayedTargetSupplementsHints(t *testing.T) {
	origin, _ := ParseName("origin.example")
	answers := []Record{{Owner: origin, Type: dnsTypeHTTPS, Class: 1, RData: svcbRData(1, []string{"service", "example"}, svcbParam(svcParamIPv4Hint, []byte{192, 0, 2, 1}))}}
	result, err := ResolveHTTPS(context.Background(), "origin.example", func(context.Context, string) ([]Record, error) {
		return answers, nil
	}, func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		select {
		case <-time.After(20 * time.Millisecond):
			return []net.IPAddr{{IP: net.ParseIP("198.51.100.2")}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, ServiceDiscoveryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Candidates[0].Addresses; len(got) != 2 {
		t.Fatalf("addresses = %v, want hint and delayed target address", got)
	}
}

func TestDiscoveryDowngradePolicy(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		kind DiscoveryFailureKind
		want bool
	}{
		{"nodata", errDNSNoData, DiscoveryFailureNODATA, true},
		{"nxdomain", errors.New("DNS response: NXDomain"), DiscoveryFailureNXDOMAIN, true},
		{"unauthenticated", errors.New("resolver timed out"), DiscoveryFailureUnauthenticated, true},
		{"authenticated", &DiscoveryError{Kind: DiscoveryFailureAuthenticated, Err: errors.New("malformed HTTPS RRset")}, DiscoveryFailureAuthenticated, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			wrapped := classifyDiscoveryError(test.err, test.kind == DiscoveryFailureAuthenticated)
			if DiscoveryFailure(wrapped) != test.kind || MayDowngrade(wrapped) != test.want {
				t.Fatalf("classified = %v/%v, want %v/%v", DiscoveryFailure(wrapped), MayDowngrade(wrapped), test.kind, test.want)
			}
		})
	}
}

func TestResolveHTTPSAuthenticatedAddressFailureDoesNotDowngradeWithHints(t *testing.T) {
	origin, _ := ParseName("origin.example")
	answers := []Record{{Owner: origin, Type: dnsTypeHTTPS, Class: 1, RData: svcbRData(1, []string{"service", "example"}, svcbParam(svcParamIPv4Hint, []byte{192, 0, 2, 1}))}}
	result, err := ResolveHTTPS(context.Background(), "origin.example", func(context.Context, string) ([]Record, error) {
		return answers, nil
	}, func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("address lookup failed")
	}, ServiceDiscoveryOptions{Authenticated: true})
	if err == nil || DiscoveryFailure(err) != DiscoveryFailureAuthenticated || MayDowngrade(err) {
		t.Fatalf("err = %v, kind = %v, may downgrade = %v", err, DiscoveryFailure(err), MayDowngrade(err))
	}
	if len(result.Candidates) != 0 {
		t.Fatalf("candidates = %v, want no fallback candidate", result.Candidates)
	}
}

func TestResolveHTTPSDoesNotResolveOriginForDifferentServiceTarget(t *testing.T) {
	origin, _ := ParseName("origin.example")
	answers := []Record{{Owner: origin, Type: dnsTypeHTTPS, Class: 1, RData: svcbRData(1, []string{"service", "example"})}}
	var lookedUp string
	result, err := ResolveHTTPS(context.Background(), "origin.example", func(_ context.Context, _ string) ([]Record, error) {
		return answers, nil
	}, func(_ context.Context, name string) ([]net.IPAddr, error) {
		lookedUp = name
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.4")}}, nil
	}, ServiceDiscoveryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if lookedUp != "service.example." || result.Candidates[0].TargetName.String() != lookedUp {
		t.Fatalf("lookup target = %q, candidate = %s", lookedUp, result.Candidates[0].TargetName)
	}
}
