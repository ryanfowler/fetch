package resolver

import (
	"context"
	"net"
	"reflect"
	"testing"
)

func TestParseResolve(t *testing.T) {
	tests := []struct {
		name  string
		value string
		host  string
		port  string
		ip    string
	}{
		{name: "IPv4", value: "example.com:443:192.0.2.10", host: "example.com", port: "443", ip: "192.0.2.10"},
		{name: "normalizes host and port", value: "EXAMPLE.COM.:0443:192.0.2.10", host: "example.com", port: "443", ip: "192.0.2.10"},
		{name: "wildcard", value: "*:80:192.0.2.10", host: "*", port: "80", ip: "192.0.2.10"},
		{name: "IPv6 address", value: "example.com:443:[2001:db8::10]", host: "example.com", port: "443", ip: "2001:db8::10"},
		{name: "IPv6 host", value: "[2001:db8::1]:443:192.0.2.10", host: "2001:db8::1", port: "443", ip: "192.0.2.10"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseResolve(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if got.Host != test.host || got.Port != test.port || got.IP.String() != test.ip {
				t.Fatalf("entry = %+v, want %s:%s:%s", got, test.host, test.port, test.ip)
			}
		})
	}

	for _, value := range []string{
		"", "example.com:443", "example.com::192.0.2.1", "example.com:0:192.0.2.1",
		"example.com:443:localhost", "example.com:443:192.0.2.1:extra", "example.com:443: [::1]",
		"example.com:443:2001:db8::1",
		"[2001:db8::1:443:192.0.2.1", "bad host:443:192.0.2.1",
	} {
		t.Run("rejects "+value, func(t *testing.T) {
			if _, err := ParseResolve(value); err == nil {
				t.Fatalf("ParseResolve(%q) succeeded, want error", value)
			}
		})
	}
}

func TestParseResolveEntries(t *testing.T) {
	got, err := ParseResolveEntries("+example.com:443:,192.0.2.1,,[2001:db8::1],")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Host != "example.com" || got[1].IP.String() != "2001:db8::1" {
		t.Fatalf("entries = %+v, want two addresses", got)
	}
}

func TestResolveAddressUsesExactMappingBeforeWildcard(t *testing.T) {
	resolver := New(Config{
		Resolve: []ResolveEntry{
			{Host: "*", Port: "443", IP: net.ParseIP("192.0.2.1")},
			{Host: "example.com", Port: "443", IP: net.ParseIP("2001:db8::1")},
		},
		SystemLookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
			t.Fatal("system lookup was used for a static mapping")
			return nil, nil
		},
	})

	got, err := resolver.ResolveAddress(context.Background(), "tcp", "EXAMPLE.COM:0443")
	if err != nil {
		t.Fatal(err)
	}
	want := []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}}
	if !reflect.DeepEqual(got.Addrs, want) {
		t.Fatalf("addresses = %v, want %v", got.Addrs, want)
	}
}

func TestResolveAddressOverrideFiltersNetwork(t *testing.T) {
	resolver := New(Config{Resolve: []ResolveEntry{
		{Host: "example.com", Port: "443", IP: net.ParseIP("192.0.2.1")},
	}})
	if _, ok, err := resolver.ResolveAddressOverride("tcp6", "example.com", "443"); !ok || err == nil {
		t.Fatalf("override = %v, %v, want a matched network error", ok, err)
	}
}
