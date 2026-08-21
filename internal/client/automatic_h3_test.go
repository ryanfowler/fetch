package client

import (
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/resolver"
)

func TestSplitAltSvc(t *testing.T) {
	values := splitAltSvc(`h3=":443"; ma=60, h3-29="edge.example:8443";ma="2", h2=":443", clear`)
	if len(values) != 4 {
		t.Fatalf("got %d Alt-Svc values, want 4", len(values))
	}
	if values[0].alpn != "h3" || values[0].host != "" || values[0].port != 443 || values[0].maxAge != time.Minute {
		t.Fatalf("first value = %+v", values[0])
	}
	if values[1].host != "edge.example" || values[1].port != 8443 || values[1].maxAge != 2*time.Second {
		t.Fatalf("second value = %+v", values[1])
	}
	if !values[3].clear {
		t.Fatalf("last value = %+v, want clear", values[3])
	}
}

func TestSplitAltSvcRejectsMalformedAuthorities(t *testing.T) {
	values := splitAltSvc(`h3="bad", h3=":0", h3="[2001:db8::1]:443"`)
	if len(values) != 1 || values[0].host != "2001:db8::1" || values[0].port != 443 {
		t.Fatalf("values = %+v", values)
	}
}

func TestAutomaticH3CacheScopesAndReplacesDNSCandidates(t *testing.T) {
	cache := newAutomaticH3Cache()
	keyA := "https://example.com:443|udp://resolver-a"
	keyB := "https://example.com:443|udp://resolver-b"
	dns := automaticH3Candidate{host: "edge.example", port: 443, addresses: []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, source: h3SourceDNS, expires: time.Now().Add(time.Hour)}
	alt := automaticH3Candidate{host: "alt.example", port: 8443, addresses: []net.IPAddr{{IP: net.ParseIP("192.0.2.2")}}, source: h3SourceAltSvc, expires: time.Now().Add(time.Hour)}
	cache.addAltSvc(keyA, alt)
	cache.replaceDNS(keyA, []automaticH3Candidate{dns})
	cache.replaceDNS(keyB, []automaticH3Candidate{dns})

	got := cache.get(keyA, time.Now())
	if len(got) != 2 || got[0].source != h3SourceAltSvc || got[1].source != h3SourceDNS {
		t.Fatalf("key A = %+v", got)
	}
	if len(cache.get(keyB, time.Now())) != 1 {
		t.Fatal("resolver-scoped cache did not retain resolver B entry")
	}

	replacement := dns
	replacement.host = "new-edge.example"
	cache.replaceDNS(keyA, []automaticH3Candidate{replacement})
	got = cache.get(keyA, time.Now())
	if len(got) != 2 || got[0].source != h3SourceAltSvc || got[1].host != "new-edge.example" {
		t.Fatalf("replacement = %+v", got)
	}
}

func TestAutomaticH3CacheExpiresCandidates(t *testing.T) {
	cache := newAutomaticH3Cache()
	key := "key"
	cache.replaceDNS(key, []automaticH3Candidate{{host: "expired", port: 443, expires: time.Unix(10, 0), source: h3SourceDNS}})
	if got := cache.get(key, time.Unix(11, 0)); len(got) != 0 {
		t.Fatalf("expired candidates = %+v", got)
	}
}

func TestServiceAdvertisesH3(t *testing.T) {
	if !serviceAdvertisesH3(resolver.ServiceCandidate{ALPN: [][]byte{[]byte("h2"), []byte("h3")}}) {
		t.Fatal("h3 was not recognized")
	}
	if serviceAdvertisesH3(resolver.ServiceCandidate{ALPN: [][]byte{[]byte("h3-29")}}) {
		t.Fatal("unsupported h3-29 was recognized")
	}
	if serviceAdvertisesH3(resolver.ServiceCandidate{ALPN: [][]byte{[]byte("h2")}}) {
		t.Fatal("h2 was recognized as h3")
	}
}

func TestAutomaticH3CacheKeyIncludesOriginAndResolver(t *testing.T) {
	u, _ := url.Parse("https://Example.com/path")
	res := resolver.New(resolver.Config{})
	key := automaticH3CacheKey(u, res)
	if key != "https://example.com:443|system" {
		t.Fatalf("cache key = %q", key)
	}
}
