package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/resolver"
)

func TestAutomaticPrepareRaceClosesUnselectedResults(t *testing.T) {
	race := newAutomaticPrepareRace(context.Background())
	winnerClosed := 0
	loserClosed := 0
	winner := race.result("tcp")
	winner.cleanup = &automaticPrepareCleanup{fn: func() { winnerClosed++ }}
	loser := race.result("h3")
	loser.cleanup = &automaticPrepareCleanup{fn: func() { loserClosed++ }}

	race.send(winner)
	got := <-race.results
	race.send(loser) // The loser is buffered before the outcome is recorded.
	race.selectResult(got)
	race.finish()

	if winnerClosed != 0 {
		t.Fatalf("selected result closed %d times, want 0", winnerClosed)
	}
	if loserClosed != 1 {
		t.Fatalf("buffered loser closed %d times, want 1", loserClosed)
	}
}

func TestAutomaticPrepareRaceClosesLateResult(t *testing.T) {
	race := newAutomaticPrepareRace(context.Background())
	closed := 0
	late := race.result("tcp")
	late.cleanup = &automaticPrepareCleanup{fn: func() { closed++ }}

	race.finish()
	race.send(late)

	if closed != 1 {
		t.Fatalf("late result closed %d times, want 1", closed)
	}
}

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

func TestAutomaticH3EvictionDefersCloseForActiveTransport(t *testing.T) {
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(name, "")
	}

	res := resolver.New(resolver.Config{})
	transport := &automaticHTTP3Transport{
		fallback:              &http.Transport{},
		resolver:              res,
		tcpTransports:         make(map[string]*http.Transport),
		h3Transports:          make(map[string]automaticH3RoundTripper),
		h3TransportCandidates: make(map[string]automaticH3Candidate),
		h3Packets:             make(map[string]net.PacketConn),
		tcpECHCandidates:      make(map[string][]resolver.ServiceCandidate),
		h3TransportStates:     make(map[automaticH3RoundTripper]*automaticH3TransportState),
		transportLastUsed:     make(map[string]time.Time),
	}

	oldKey := "https://origin-00.example:443|system"
	old := newBlockingAutomaticH3Transport()
	for i := 0; i < automaticTransportOriginLimit; i++ {
		key := fmt.Sprintf("https://origin-%02d.example:443|system", i)
		candidate := newBlockingAutomaticH3Transport()
		if i == 0 {
			key = oldKey
			candidate = old
		}
		transport.h3Transports[key] = candidate
		active := 1
		if i == 0 {
			active = 0
		}
		lastUsed := time.Now().Add(time.Duration(i) * time.Second)
		transport.h3TransportStates[candidate] = &automaticH3TransportState{
			active:   active,
			lastUsed: lastUsed,
		}
		transport.transportLastUsed[key] = lastUsed
	}

	requestDone := make(chan struct {
		resp *http.Response
		err  error
	}, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, oldKey[:len(oldKey)-len("|system")]+"/", nil)
		if err != nil {
			requestDone <- struct {
				resp *http.Response
				err  error
			}{err: err}
			return
		}
		resp, err := transport.RoundTrip(req)
		requestDone <- struct {
			resp *http.Response
			err  error
		}{resp: resp, err: err}
	}()

	select {
	case <-old.started:
	case <-time.After(time.Second):
		t.Fatal("active HTTP/3 request did not start")
	}

	newKey := "https://new-origin.example:443|system"
	newTransport := newBlockingAutomaticH3Transport()
	transport.mu.Lock()
	transport.h3Transports[newKey] = newTransport
	transport.h3TransportStates[newTransport] = &automaticH3TransportState{
		active:   1,
		lastUsed: time.Now(),
	}
	transport.transportLastUsed[newKey] = time.Now()
	closeH3 := transport.evictTransportOriginLocked(newKey)
	oldState := transport.h3TransportStates[old]
	transport.mu.Unlock()
	closeH3Transports(closeH3)

	if len(closeH3) != 0 {
		t.Fatalf("eviction closed %d active HTTP/3 transports", len(closeH3))
	}
	if oldState == nil || !oldState.evicted || oldState.active == 0 {
		t.Fatalf("old transport state after eviction = %+v", oldState)
	}
	if old.wasClosed() {
		t.Fatal("active HTTP/3 transport was closed during eviction")
	}

	close(old.release)
	var result struct {
		resp *http.Response
		err  error
	}
	select {
	case result = <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("first HTTP/3 request did not complete after eviction")
	}
	if result.err != nil {
		t.Fatalf("first HTTP/3 request failed after eviction: %v", result.err)
	}
	if result.resp == nil || result.resp.Body == nil {
		t.Fatal("first HTTP/3 request returned no response body")
	}
	if old.wasClosed() {
		t.Fatal("evicted HTTP/3 transport closed before response body cleanup")
	}
	if err := result.resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.closed:
	case <-time.After(time.Second):
		t.Fatal("evicted HTTP/3 transport was not closed after the last user left")
	}

	transport.mu.Lock()
	for _, state := range transport.h3TransportStates {
		state.active = 0
	}
	transport.mu.Unlock()
	_ = transport.Close()
}

type blockingAutomaticH3Transport struct {
	started   chan struct{}
	release   chan struct{}
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newBlockingAutomaticH3Transport() *blockingAutomaticH3Transport {
	return &blockingAutomaticH3Transport{
		started: make(chan struct{}),
		release: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (t *blockingAutomaticH3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.startOnce.Do(func() { close(t.started) })
	select {
	case <-t.release:
	case <-t.closed:
		return nil, context.Canceled
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}, nil
}

func (t *blockingAutomaticH3Transport) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func (t *blockingAutomaticH3Transport) CloseIdleConnections() {}

func (t *blockingAutomaticH3Transport) wasClosed() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}
