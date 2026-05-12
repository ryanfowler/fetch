package dnsinspect

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"

	"golang.org/x/net/dns/dnsmessage"
)

func TestInspectDOHShowsAAndAAAATTLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "A":
			io.WriteString(w, `{"Status":0,"Answer":[{"type":5,"data":"alias.example.com.","TTL":120},{"type":1,"data":"192.0.2.1","TTL":60}]}`)
		case "AAAA":
			io.WriteString(w, `{"Status":0,"Answer":[{"type":28,"data":"2001:db8::1","TTL":300}]}`)
		case "TXT":
			io.WriteString(w, `{"Status":0,"Answer":[{"type":16,"data":"v=spf1 -all","TTL":180}]}`)
		default:
			io.WriteString(w, `{"Status":0}`)
		}
	}))
	defer server.Close()

	p := core.TestPrinter(false)
	status := Inspect(context.Background(), p, &Config{
		DNSServer: mustURL(t, server.URL+"/dns-query"),
		URL:       mustURL(t, "https://example.com"),
	})
	if status != 0 {
		t.Fatalf("status = %d, want 0\n%s", status, p.Bytes())
	}
	out := string(p.Bytes())
	for _, want := range []string{
		"DNS lookup: example.com",
		"Resolver: " + server.URL + "/dns-query",
		"A\n",
		"\u2514\u2500 192.0.2.1 (TTL 1m)",
		"AAAA\n",
		"\u2514\u2500 2001:db8::1 (TTL 5m)",
		"CNAME\n",
		"alias.example.com. (TTL 2m)",
		"TXT\n",
		"v=spf1 -all (TTL 3m)",
		"Addresses: 2",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestInspectIPLiteralSkipsLookup(t *testing.T) {
	p := core.TestPrinter(false)
	status := Inspect(context.Background(), p, &Config{
		URL: mustURL(t, "http://127.0.0.1"),
	})
	if status != 0 {
		t.Fatalf("status = %d, want 0\n%s", status, p.Bytes())
	}
	out := string(p.Bytes())
	if !strings.Contains(out, "IP literal: 127.0.0.1 (no DNS query needed)") {
		t.Fatalf("output missing IP literal message:\n%s", out)
	}
}

func TestLookupQueriesRecordTypesConcurrently(t *testing.T) {
	var mu sync.Mutex
	active := 0
	maxActive := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()

		time.Sleep(25 * time.Millisecond)

		mu.Lock()
		active--
		mu.Unlock()

		switch r.URL.Query().Get("type") {
		case "A":
			io.WriteString(w, `{"Status":0,"Answer":[{"type":1,"data":"192.0.2.1","TTL":60}]}`)
		default:
			io.WriteString(w, `{"Status":0}`)
		}
	}))
	defer server.Close()

	_, err := lookup(context.Background(), &Config{
		DNSServer: mustURL(t, server.URL+"/dns-query"),
	}, "example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	got := maxActive
	mu.Unlock()
	if got < 2 {
		t.Fatalf("max concurrent requests = %d, want at least 2", got)
	}
}

func TestLookupCollapsesDuplicateCNAMEsWithLowestTTL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "A":
			io.WriteString(w, `{"Status":0,"Answer":[{"type":5,"data":"alias.example.com.","TTL":120},{"type":1,"data":"192.0.2.1","TTL":60}]}`)
		case "AAAA":
			io.WriteString(w, `{"Status":0,"Answer":[{"type":5,"data":"alias.example.com.","TTL":119}]}`)
		default:
			io.WriteString(w, `{"Status":0}`)
		}
	}))
	defer server.Close()

	res, err := lookup(context.Background(), &Config{
		DNSServer: mustURL(t, server.URL+"/dns-query"),
	}, "example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cnames := res.records["CNAME"]
	if len(cnames) != 1 {
		t.Fatalf("CNAME records = %v, want 1 collapsed record", cnames)
	}
	if got, want := cnames[0].ttl, uint32(119); got != want {
		t.Fatalf("CNAME TTL = %d, want lowest TTL %d", got, want)
	}
}

func TestLookupUDPRecordsReturnsTTL(t *testing.T) {
	addr, stop := startUDPServer(t)
	defer stop()

	records, err := lookupUDPRecords(context.Background(), addr, "example.com", queryType{
		label:   "A",
		dohType: "A",
		dnsType: dnsmessage.TypeA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %v, want 1 record", records)
	}
	if got, want := records[0].value, "192.0.2.10"; got != want {
		t.Fatalf("value = %q, want %q", got, want)
	}
	if got, want := records[0].ttl, uint32(42); got != want {
		t.Fatalf("TTL = %d, want %d", got, want)
	}
}

func TestLookupUsesDefaultResolverWhenNoSystemDNSServerDiscovered(t *testing.T) {
	origReadResolvConf := readResolvConf
	origDefaultLookupIPAddr := defaultLookupIPAddr
	t.Cleanup(func() {
		readResolvConf = origReadResolvConf
		defaultLookupIPAddr = origDefaultLookupIPAddr
	})

	readResolvConf = func() ([]byte, error) {
		return nil, errors.New("missing resolv.conf")
	}
	var lookedUpHost string
	defaultLookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		lookedUpHost = host
		return []net.IPAddr{
			{IP: net.ParseIP("192.0.2.44")},
			{IP: net.ParseIP("2001:db8::44")},
		}, nil
	}

	res, err := lookup(context.Background(), &Config{}, "example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if lookedUpHost != "example.com" {
		t.Fatalf("default resolver looked up host %q, want example.com", lookedUpHost)
	}
	if strings.Contains(res.resolver, "127.0.0.1") {
		t.Fatalf("resolver label = %q, must not silently fall back to loopback", res.resolver)
	}
	if got, want := res.records["A"][0].value, "192.0.2.44"; got != want {
		t.Fatalf("A record = %q, want %q", got, want)
	}
	if got, want := res.records["AAAA"][0].value, "2001:db8::44"; got != want {
		t.Fatalf("AAAA record = %q, want %q", got, want)
	}
	if res.records["A"][0].hasTTL || res.records["AAAA"][0].hasTTL {
		t.Fatalf("default resolver records unexpectedly reported TTLs: %#v", res.records)
	}
}

func TestResolverTargetDoesNotDefaultToLoopback(t *testing.T) {
	origReadResolvConf := readResolvConf
	t.Cleanup(func() {
		readResolvConf = origReadResolvConf
	})

	readResolvConf = func() ([]byte, error) {
		return []byte("# no nameservers\n"), nil
	}

	target := resolverTarget(nil)
	if !target.useDefault {
		t.Fatalf("useDefault = false, want true")
	}
	if strings.Contains(target.label, "127.0.0.1") || strings.Contains(target.udpAddr, "127.0.0.1") {
		t.Fatalf("resolver target silently used loopback: %#v", target)
	}
}

func TestRenderShowsUnavailableTTLPerRecord(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host:     "example.com",
		resolver: "system",
		records: map[string][]record{
			"A": {{typ: "A", value: "192.0.2.1", ttl: 60, hasTTL: true}},
		},
	})

	out := string(p.Bytes())
	if !strings.Contains(out, "\u2514\u2500 192.0.2.1 (TTL 1m)") {
		t.Fatalf("output missing tree-formatted TTL:\n%s", out)
	}
}

func TestRenderSortsRecordsWithinType(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host:     "example.com",
		resolver: "system",
		records: map[string][]record{
			"A": {
				{typ: "A", value: "192.0.2.20", ttl: 60, hasTTL: true},
				{typ: "A", value: "192.0.2.10", ttl: 60, hasTTL: true},
			},
		},
	})

	out := string(p.Bytes())
	first := strings.Index(out, "192.0.2.10")
	second := strings.Index(out, "192.0.2.20")
	if first == -1 || second == -1 || first > second {
		t.Fatalf("records not sorted within type:\n%s", out)
	}
}

func TestFormatTTLTrimsZeroUnits(t *testing.T) {
	tests := map[int]string{
		1:    "1s",
		60:   "1m",
		300:  "5m",
		3600: "1h",
		3660: "1h1m",
	}
	for ttl, want := range tests {
		if got := formatTTL(uint32(ttl)); got != want {
			t.Fatalf("formatTTL(%d) = %q, want %q", ttl, got, want)
		}
	}
}

func TestFormatCAA(t *testing.T) {
	raw := append([]byte{0, 5}, []byte("issueletsencrypt.org")...)
	if got, want := formatCAA(raw), `0 issue "letsencrypt.org"`; got != want {
		t.Fatalf("formatCAA = %q, want %q", got, want)
	}
}

func TestNormalizeDOHHTTPSGenericRDATA(t *testing.T) {
	got := normalizeDOHValue(dnsmessage.TypeHTTPS, `\# 24 000100000100030268330003000201bb00040004c0000201`)
	for _, want := range []string{
		"1 .",
		"ALPN=h3",
		"Port=443",
		"IPv4Hint=192.0.2.1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("decoded HTTPS value missing %q: %q", want, got)
		}
	}
}

func TestNormalizeDOHCAAGenericRDATA(t *testing.T) {
	got := normalizeDOHValue(dnsTypeCAA, `\# 22 000569737375656c657473656e63727970742e6f7267`)
	if want := `0 issue "letsencrypt.org"`; got != want {
		t.Fatalf("decoded CAA = %q, want %q", got, want)
	}
}

func TestInspectDOHFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"Status":3}`)
	}))
	defer server.Close()

	p := core.TestPrinter(false)
	status := Inspect(context.Background(), p, &Config{
		DNSServer: mustURL(t, server.URL),
		URL:       mustURL(t, "https://missing.example"),
	})
	if status != 1 {
		t.Fatalf("status = %d, want 1", status)
	}
	if out := string(p.Bytes()); !strings.Contains(out, "NXDomain") {
		t.Fatalf("output missing NXDomain:\n%s", out)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func startUDPServer(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Message
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			if len(req.Questions) == 0 {
				continue
			}
			res := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 req.Header.ID,
					Response:           true,
					RecursionDesired:   req.Header.RecursionDesired,
					RecursionAvailable: true,
					RCode:              dnsmessage.RCodeSuccess,
				},
				Questions: req.Questions,
			}
			if req.Questions[0].Type == dnsmessage.TypeA {
				res.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Name:  req.Questions[0].Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   42,
					},
					Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}},
				}}
			}
			raw, err := res.Pack()
			if err == nil {
				_, _ = conn.WriteTo(raw, addr)
			}
		}
	}()

	return conn.LocalAddr().String(), func() {
		_ = conn.Close()
		<-done
	}
}
