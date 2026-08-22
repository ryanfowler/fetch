package client

import (
	"net/url"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"
)

func TestECHDiscoveryNeedsWarningByResolverSecurity(t *testing.T) {
	target, _ := url.Parse("https://example.com/")
	verified, err := resolver.ParseEndpoint("https://dns.example/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		endpoint *resolver.Endpoint
		insecure bool
		want     bool
	}{
		{"system", nil, false, true},
		{"udp", mustEndpoint(t, "udp://127.0.0.1"), false, true},
		{"verified doh", verified, false, false},
		{"insecure doh", verified, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ECHDiscoveryNeedsWarning(core.ECHAuto, target, test.endpoint, test.insecure, nil); got != test.want {
				t.Fatalf("warning = %v, want %v", got, test.want)
			}
		})
	}
}

func TestECHDiscoveryNeedsWarningSkipsDisabledAndProxiedRequests(t *testing.T) {
	target, _ := url.Parse("https://example.com/")
	proxy, _ := url.Parse("http://127.0.0.1:8080")
	if ECHDiscoveryNeedsWarning(core.ECHOff, target, nil, false, nil) {
		t.Fatal("ECH off should not warn")
	}
	if ECHDiscoveryNeedsWarning(core.ECHAuto, target, nil, false, proxy) {
		t.Fatal("proxied ECH should not warn")
	}
}

func mustEndpoint(t *testing.T, value string) *resolver.Endpoint {
	t.Helper()
	endpoint, err := resolver.ParseEndpoint(value)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}
