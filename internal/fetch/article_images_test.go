package fetch

import (
	"context"
	"net"
	"net/url"
	"testing"
)

func TestSafeArticleImageURLRejectsNonPublicResolvedAddresses(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{name: "shared", ip: "100.100.100.200"},
		{name: "metadata", ip: "169.254.169.254"},
		{name: "documentation", ip: "192.0.2.10"},
		{name: "ipv6 documentation", ip: "2001:db8::10"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := url.Parse("https://images.example/photo.jpg")
			if err != nil {
				t.Fatal(err)
			}
			lookup := func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP(test.ip)}}, nil
			}
			if safeArticleImageURL(context.Background(), target, lookup) {
				t.Fatalf("safeArticleImageURL accepted %s", test.ip)
			}
		})
	}
}

func TestSafeArticleImageURLAcceptsPublicResolvedAddress(t *testing.T) {
	target, err := url.Parse("https://images.example/photo.jpg")
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.114.10")}}, nil
	}
	if !safeArticleImageURL(context.Background(), target, lookup) {
		t.Fatal("safeArticleImageURL rejected a public address")
	}
}
