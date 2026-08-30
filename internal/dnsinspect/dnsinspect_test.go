package dnsinspect

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"

	"golang.org/x/net/dns/dnsmessage"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, io.ErrShortWrite
}

type brokenPipeWriter struct{}

func (brokenPipeWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestInspectWithErrorSeparatesOutput(t *testing.T) {
	output := core.TestPrinter(false)
	errors := core.TestPrinter(false)

	status := InspectWithError(context.Background(), output, errors, &Config{
		URL: mustURL(t, "http://192.0.2.1"),
	})
	if status != 0 {
		t.Fatalf("status = %d, want 0", status)
	}
	if !strings.Contains(string(output.Bytes()), "Status: IP literal — DNS not performed") {
		t.Fatalf("inspection output = %q, want IP literal status", output.Bytes())
	}
	if len(errors.Bytes()) != 0 {
		t.Fatalf("error output = %q, want empty", errors.Bytes())
	}
}

func TestInspectWithErrorSeparatesSetupErrors(t *testing.T) {
	output := core.TestPrinter(false)
	errors := core.TestPrinter(false)

	status := InspectWithError(context.Background(), output, errors, &Config{
		URL: mustURL(t, "https:///missing-host"),
	})
	if status != 1 {
		t.Fatalf("status = %d, want 1", status)
	}
	if len(output.Bytes()) != 0 {
		t.Fatalf("inspection output = %q, want empty", output.Bytes())
	}
	if !strings.Contains(string(errors.Bytes()), "--inspect-dns requires a hostname") {
		t.Fatalf("error output = %q, want setup error", errors.Bytes())
	}
}

func TestFlushInspectionOutputReportsWriteErrors(t *testing.T) {
	output := core.TestPrinter(false).NewWriter(failingWriter{})
	errors := core.TestPrinter(false)
	output.WriteString("inspection")

	if code := flushInspectionOutput(output, errors); code != 1 {
		t.Fatalf("flushInspectionOutput() exit code = %d, want 1", code)
	}
	if !strings.Contains(string(errors.Bytes()), "short write") {
		t.Fatalf("error output = %q, want write error", errors.Bytes())
	}
}

func TestFlushInspectionOutputIgnoresBrokenPipe(t *testing.T) {
	output := core.TestPrinter(false).NewWriter(brokenPipeWriter{})
	errors := core.TestPrinter(false)
	output.WriteString("inspection")

	if code := flushInspectionOutput(output, errors); code != 0 {
		t.Fatalf("flushInspectionOutput() exit code = %d, want 0", code)
	}
	if len(errors.Bytes()) != 0 {
		t.Fatalf("error output = %q, want empty", errors.Bytes())
	}
}

func TestInspectDOHShowsAAndAAAATTLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "A":
			io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com.","type":5,"data":"alias.example.com.","TTL":120},{"name":"alias.example.com.","type":1,"data":"192.0.2.1","TTL":60}]}`)
		case "AAAA":
			io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com.","type":28,"data":"2001:db8::1","TTL":300}]}`)
		case "TXT":
			io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com.","type":16,"data":"v=spf1 -all","TTL":180}]}`)
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
		"* Lookup\n",
		"Name: example.com",
		"Resolver: " + server.URL + "/dns-query",
		"Transport: HTTPS (DoH)",
		"Transport security: plaintext",
		"Source: configured resolver endpoint",
		"Status: complete",
		"Results: 2 addresses · 4 records · 4 record types",
		"Queries: 11 total · 3 with data · 8 no data",
		"Timing: ",
		"* Records\n",
		"\u2514\u2500 192.0.2.1 (TTL 1m)",
		"\u2514\u2500 2001:db8::1 (TTL 5m)",
		"alias.example.com. (TTL 2m)",
		"v=spf1 -all (TTL 3m)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestDNSQueryHostPreservesASCIIServiceLabels(t *testing.T) {
	got, err := dnsQueryHost("_acme-challenge.example")
	if err != nil {
		t.Fatal(err)
	}
	if want := "_acme-challenge.example"; got != want {
		t.Fatalf("DNS query host = %q, want %q", got, want)
	}
}

func TestInspectNormalizesIDNForDNSQueries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		if got, want := r.URL.Query().Get("name"), "xn--mnich-kva.example"; got != want {
			http.Error(w, "unexpected DNS name", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("type") == "A" {
			io.WriteString(w, `{"Status":0,"Answer":[{"name":"xn--mnich-kva.example.","type":1,"data":"192.0.2.1","TTL":60}]}`)
			return
		}
		io.WriteString(w, `{"Status":0}`)
	}))
	defer server.Close()

	p := core.TestPrinter(false)
	status := Inspect(context.Background(), p, &Config{
		DNSServer: mustURL(t, server.URL),
		URL:       mustURL(t, "https://münich.example"),
	})
	if status != 0 {
		t.Fatalf("status = %d, want 0\n%s", status, p.Bytes())
	}
	if !strings.Contains(string(p.Bytes()), "192.0.2.1") {
		t.Fatalf("output missing IDN A record:\n%s", p.Bytes())
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
	for _, want := range []string{
		"Lookup\n",
		"Name: 127.0.0.1",
		"Status: IP literal — DNS not performed",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"Resolver:", "Transport:", "Transport security:", "Timing:"} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("IP literal output contains DNS field %q:\n%s", unwanted, out)
		}
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
			io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com.","type":1,"data":"192.0.2.1","TTL":60}]}`)
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

func TestInspectKeepsRecordsAndFailsOnPartialQueryError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Force the JSON compatibility path. The query type is carried in
			// the subsequent GET request.
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		switch r.URL.Query().Get("type") {
		case "A":
			io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com.","type":1,"data":"192.0.2.1","TTL":60}]}`)
		case "TXT":
			io.WriteString(w, `{"Status":2}`)
		default:
			io.WriteString(w, `{"Status":0}`)
		}
	}))
	defer server.Close()

	output := core.TestPrinter(false)
	errors := core.TestPrinter(false)
	status := InspectWithError(context.Background(), output, errors, &Config{
		DNSServer: mustURL(t, server.URL+"/dns-query"),
		URL:       mustURL(t, "https://example.com"),
	})
	if status != 1 {
		t.Fatalf("status = %d, want partial-result status 1\n%s", status, output.Bytes())
	}
	out := string(output.Bytes())
	for _, want := range []string{
		"192.0.2.1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("partial output missing %q:\n%s", want, out)
		}
	}
	if got := string(errors.Bytes()); got != "" {
		t.Fatalf("partial error output = %q, want empty", got)
	}
	for _, want := range []string{"Status: incomplete — 1 of 11 queries failed", "Failures", "TXT:", "ServFail"} {
		if !strings.Contains(out, want) {
			t.Fatalf("partial output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderFailuresGroupsIdenticalErrors(t *testing.T) {
	p := core.TestPrinter(false)
	err := errors.New("SERVFAIL")
	renderFailures(p, []queryFailure{
		{label: "TXT", err: err},
		{label: "A", err: err},
		{label: "AAAA", err: err},
	})

	out := string(p.Bytes())
	if !strings.Contains(out, "A, AAAA, TXT: SERVFAIL") {
		t.Fatalf("grouped failure output = %q, want grouped labels", out)
	}
	if strings.Count(out, "SERVFAIL") != 1 {
		t.Fatalf("grouped failure output = %q, want one diagnostic", out)
	}
}

func TestRenderFailuresKeepsDistinctLongErrorsDistinct(t *testing.T) {
	prefix := strings.Repeat("x", maxPartialErrorBytes)
	first := errors.New(prefix + "first")
	second := errors.New(prefix + "second")
	p := core.TestPrinter(false)
	renderFailures(p, []queryFailure{
		{label: "A", err: first},
		{label: "AAAA", err: second},
	})

	out := string(p.Bytes())
	if strings.Count(out, prefix[:maxPartialErrorBytes-3]) != 2 {
		t.Fatalf("distinct failures were grouped or not bounded: %q", out)
	}
	if !strings.Contains(out, "A: "+prefix+"...") ||
		!strings.Contains(out, "AAAA: "+prefix+"...") {
		t.Fatalf("bounded failure output = %q, want both diagnostics", out)
	}
	if strings.Contains(out, "first") || strings.Contains(out, "second") {
		t.Fatalf("failure output was not bounded: %q", out)
	}
}

func TestRenderFailuresUsesAllRecordTypesOnlyForCompleteSet(t *testing.T) {
	p := core.TestPrinter(false)
	failures := make([]queryFailure, 0, len(inspectTypes))
	for _, typ := range inspectTypes {
		failures = append(failures, queryFailure{label: typ.label, err: errors.New("SERVFAIL")})
	}
	renderFailures(p, failures)
	if out := string(p.Bytes()); !strings.Contains(out, "All record types: SERVFAIL") {
		t.Fatalf("all-type failure output = %q, want aggregate label", out)
	}

	p = core.TestPrinter(false)
	failures[0].label = failures[1].label
	renderFailures(p, failures)
	if out := string(p.Bytes()); strings.Contains(out, "All record types:") {
		t.Fatalf("duplicate labels incorrectly treated as all types: %q", out)
	}
}

func TestInspectPartialFailureIsSilentButNonzero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		if r.URL.Query().Get("type") == "A" {
			io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com.","type":1,"data":"192.0.2.1","TTL":60}]}`)
			return
		}
		if r.URL.Query().Get("type") == "TXT" {
			io.WriteString(w, `{"Status":2}`)
			return
		}
		io.WriteString(w, `{"Status":0}`)
	}))
	defer server.Close()

	p := core.TestPrinter(false)
	status := Inspect(context.Background(), p, &Config{
		DNSServer: mustURL(t, server.URL),
		URL:       mustURL(t, "https://example.com"),
		Silent:    true,
	})
	if status != 1 {
		t.Fatalf("status = %d, want 1", status)
	}
	if out := string(p.Bytes()); strings.Contains(out, "warning: DNS inspection incomplete") {
		t.Fatalf("silent inspection emitted warning:\n%s", out)
	}
	if !strings.Contains(string(p.Bytes()), "192.0.2.1") {
		t.Fatalf("silent inspection lost successful records:\n%s", p.Bytes())
	}
}

func TestLookupCollapsesDuplicateCNAMEsWithLowestTTL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "A":
			io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com.","type":5,"data":"alias.example.com.","TTL":120},{"name":"alias.example.com.","type":1,"data":"192.0.2.1","TTL":60}]}`)
		case "AAAA":
			io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com.","type":5,"data":"alias.example.com.","TTL":119}]}`)
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

func TestLookupWithoutExplicitServerUsesPlatformResolver(t *testing.T) {
	origDefaultLookupIPAddr := defaultLookupIPAddr
	t.Cleanup(func() {
		defaultLookupIPAddr = origDefaultLookupIPAddr
	})

	defaultLookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("192.0.2.44")},
			{IP: net.ParseIP("2001:db8::44")},
		}, nil
	}

	// A resolv.conf with no nameservers forces the platform fallback path.
	res, err := lookup(context.Background(), &Config{ResolvConfPath: emptyResolvConf(t)}, "example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.resolver != "system resolver" {
		t.Fatalf("resolver label = %q, want system resolver", res.resolver)
	}
	if !res.ttlUnavailable {
		t.Fatal("ttlUnavailable = false, want true")
	}
	if got := recordCount(res); got != 2 {
		t.Fatalf("record count = %d, want only platform A/AAAA records", got)
	}
	if len(res.records) != 2 || len(res.records["A"]) != 1 || len(res.records["AAAA"]) != 1 {
		t.Fatalf("platform records = %#v, want only A and AAAA", res.records)
	}
}

func TestLookupUsesPlatformResolver(t *testing.T) {
	origDefaultLookupIPAddr := defaultLookupIPAddr
	t.Cleanup(func() {
		defaultLookupIPAddr = origDefaultLookupIPAddr
	})

	var lookedUpHost string
	defaultLookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		lookedUpHost = host
		return []net.IPAddr{
			{IP: net.ParseIP("192.0.2.44")},
			{IP: net.ParseIP("2001:db8::44")},
		}, nil
	}

	res, err := lookup(context.Background(), &Config{ResolvConfPath: emptyResolvConf(t)}, "example.com", time.Now())
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

func TestLookupSystemNameserverReturnsTTL(t *testing.T) {
	addr, stop := startUDPServer(t)
	defer stop()

	// Select the test UDP server as the system nameserver via a direct policy,
	// so inspection queries a real nameserver and keeps TTLs.
	res, err := lookup(context.Background(), &Config{SystemPolicy: &resolver.SystemResolverPolicy{
		Nameservers: []string{addr},
		Attempts:    1,
		Timeout:     time.Second,
	}}, "example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.resolver != addr {
		t.Fatalf("resolver label = %q, want %q", res.resolver, addr)
	}
	if res.ttlUnavailable {
		t.Fatal("ttlUnavailable = true, want false for a direct nameserver query")
	}
	if got := len(res.records["A"]); got != 1 {
		t.Fatalf("A records = %d, want 1", got)
	}
	if got, want := res.records["A"][0].value, "192.0.2.10"; got != want {
		t.Fatalf("A value = %q, want %q", got, want)
	}
	if got, want := res.records["A"][0].ttl, uint32(42); got != want {
		t.Fatalf("A TTL = %d, want %d", got, want)
	}
}

func TestLookupSystemFallsBackToPlatform(t *testing.T) {
	origDefaultLookupIPAddr := defaultLookupIPAddr
	t.Cleanup(func() {
		defaultLookupIPAddr = origDefaultLookupIPAddr
	})

	// A policy pointing at a dead nameserver: every record type fails, so
	// inspection must fall back to the platform resolver for A/AAAA.
	defaultLookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.99")}}, nil
	}

	res, err := lookup(context.Background(), &Config{SystemPolicy: &resolver.SystemResolverPolicy{
		Nameservers: []string{"127.0.0.1:1"},
		Attempts:    1,
		Timeout:     50 * time.Millisecond,
	}}, "example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.resolver != "system resolver (configured nameservers) (platform fallback)" {
		t.Fatalf("resolver label = %q, want platform fallback label", res.resolver)
	}
	if !res.ttlUnavailable {
		t.Fatal("ttlUnavailable = false, want true for platform fallback")
	}
	if got := len(res.records["A"]); got != 1 {
		t.Fatalf("A records = %d, want 1", got)
	}
	if got, want := res.records["A"][0].value, "192.0.2.99"; got != want {
		t.Fatalf("A value = %q, want %q", got, want)
	}
	if len(res.failures) == 0 {
		t.Fatal("platform fallback discarded direct nameserver failures")
	}
	if got, want := len(res.queries), len(inspectTypes); got != want {
		t.Fatalf("platform fallback query results = %d, want %d", got, want)
	}
	for i, query := range res.queries {
		if query.status != queryStatusFailed {
			t.Errorf("platform fallback query %d status = %d, want failed", i, query.status)
		}
	}

	p := core.TestPrinter(false)
	status := Inspect(context.Background(), p, &Config{
		SystemPolicy: &resolver.SystemResolverPolicy{
			Nameservers: []string{"127.0.0.1:1"},
			Attempts:    1,
			Timeout:     50 * time.Millisecond,
		},
		URL: mustURL(t, "https://example.com"),
	})
	if status != 1 || !strings.Contains(string(p.Bytes()), "Status: incomplete") {
		t.Fatalf("platform fallback status/output = %d/%s, want status 1 and incomplete result", status, p.Bytes())
	}
}

// emptyResolvConf returns a resolv.conf path that lists no nameservers, so
// lookup() takes the platform-resolver fallback path deterministically.
func emptyResolvConf(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/resolv.conf"
	if err := os.WriteFile(path, []byte("search example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolverTargetUsesPlatformResolver(t *testing.T) {
	target := resolverTarget(nil)
	if !target.useDefault {
		t.Fatalf("useDefault = false, want true")
	}
	if strings.Contains(target.label, "127.0.0.1") || strings.Contains(target.udpAddr, "127.0.0.1") {
		t.Fatalf("resolver target silently used loopback: %#v", target)
	}
}

func TestRenderSeparatesWarnings(t *testing.T) {
	output := core.TestPrinter(false)
	errors := core.TestPrinter(false)
	renderWithWarning(output, errors, &result{tcpFallback: true})

	if strings.Contains(string(output.Bytes()), "UDP response was truncated") {
		t.Fatalf("output contains TCP fallback warning: %q", output.Bytes())
	}
	if !strings.Contains(string(errors.Bytes()), "UDP response was truncated") {
		t.Fatalf("error output missing TCP fallback warning: %q", errors.Bytes())
	}
}

func TestRenderStructuredLookupOmitsUnavailableFields(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{host: "example.com", records: map[string][]record{}})

	out := string(p.Bytes())
	for _, want := range []string{
		"Lookup\n",
		"Name: example.com",
		"Status: complete",
		"Results: 0 addresses · 0 records · 0 record types",
		"Records\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("structured output missing %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"Resolver:", "Transport:", "Source:", "Queries:", "Timing:"} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("structured output contains empty field %q:\n%s", unwanted, out)
		}
	}
}

func TestRenderStructuredLookupShowsNormalizedQueryName(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host:      "münich.example",
		queryName: "xn--mnich-kva.example",
		records:   map[string][]record{},
	})

	if out := string(p.Bytes()); !strings.Contains(out, "Query name: xn--mnich-kva.example") {
		t.Fatalf("structured output missing normalized query name:\n%s", out)
	}
}

func TestRenderStructuredLookupUsesSingularGrammar(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host:          "example.com",
		resolver:      "192.0.2.53:53",
		transport:     "UDP",
		security:      string(resolver.SecurityPlaintext),
		source:        "system resolver configuration",
		queryTotal:    1,
		queryWithData: 1,
		duration:      time.Millisecond,
		records: map[string][]record{
			"A": {{typ: "A", value: "192.0.2.1", hasTTL: true, ttl: 60}},
		},
	})

	out := string(p.Bytes())
	for _, want := range []string{
		"Results: 1 address · 1 record · 1 record type",
		"Queries: 1 total · 1 with data · 0 no data",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("structured output missing %q:\n%s", want, out)
		}
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

func TestRenderShowsUnavailableTTLOnRecord(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host: "printer.local",
		records: map[string][]record{
			"A": {{typ: "A", value: "192.0.2.1"}},
		},
	})

	if out := string(p.Bytes()); !strings.Contains(out, "192.0.2.1 (TTL unavailable)") {
		t.Fatalf("output missing unavailable record TTL:\n%s", out)
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

func TestAggregatePreservesEveryQueryStatus(t *testing.T) {
	out := &result{records: make(map[string][]record)}
	results := []queryResult{
		{typ: inspectTypes[0], records: []record{{typ: "A", value: "192.0.2.1"}}},
		{typ: inspectTypes[1], err: resolver.ErrDNSNoData},
		{typ: inspectTypes[2], err: errors.New("SERVFAIL")},
		{typ: inspectTypes[3]},
	}

	if err := aggregate(out, results, time.Now()); err == nil {
		t.Fatal("aggregate() error = nil, want query failure")
	}
	if got, want := len(out.queries), len(results); got != want {
		t.Fatalf("preserved query results = %d, want %d", got, want)
	}
	for i, want := range []queryStatus{
		queryStatusData,
		queryStatusNoData,
		queryStatusFailed,
		queryStatusNoData,
	} {
		if got := out.queries[i].status; got != want {
			t.Errorf("query %d status = %d, want %d", i, got, want)
		}
		if got, wantType := out.queries[i].typ, results[i].typ; got != wantType {
			t.Errorf("query %d type = %#v, want %#v", i, got, wantType)
		}
	}
	if got, want := out.queryTotal, 4; got != want {
		t.Errorf("query total = %d, want %d", got, want)
	}
	if got, want := out.queryWithData, 1; got != want {
		t.Errorf("queries with data = %d, want %d", got, want)
	}
	if got, want := out.queryNoData, 2; got != want {
		t.Errorf("queries with no data = %d, want %d", got, want)
	}
	if got, want := len(out.failures), 1; got != want {
		t.Errorf("query failures = %d, want %d", got, want)
	}
}

func TestInspectAllNODATAIsSuccessful(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"Status":0}`)
	}))
	defer server.Close()

	p := core.TestPrinter(false)
	status := Inspect(context.Background(), p, &Config{
		DNSServer: mustURL(t, server.URL),
		URL:       mustURL(t, "https://empty.example"),
	})
	if status != 0 {
		t.Fatalf("status = %d, want 0\n%s", status, p.Bytes())
	}
	out := string(p.Bytes())
	for _, want := range []string{
		"Status: complete",
		"Results: 0 addresses · 0 records · 0 record types",
		"Queries: 11 total · 0 with data · 11 no data",
		"Records\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("all-NODATA output missing %q:\n%s", want, out)
		}
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
