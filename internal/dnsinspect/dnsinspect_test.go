package dnsinspect

import (
	"context"
	"encoding/hex"
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

func TestResolverTransportSecurityReportsTransportProtection(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		insecure  bool
		transport string
		security  string
	}{
		{name: "UDP", endpoint: "udp://192.0.2.53", transport: "UDP", security: "plaintext"},
		{name: "TCP", endpoint: "tcp://192.0.2.53", transport: "TCP", security: "plaintext"},
		{name: "DoT", endpoint: "dot://resolver.example", transport: "TLS (DoT)", security: "verified TLS"},
		{name: "DoQ", endpoint: "doq://resolver.example", transport: "QUIC (DoQ)", security: "verified TLS"},
		{name: "DoH", endpoint: "https://resolver.example/dns-query", transport: "HTTPS (DoH)", security: "verified TLS"},
		{name: "DoT insecure", endpoint: "dot://resolver.example", insecure: true, transport: "TLS (DoT)", security: "encrypted, certificate verification disabled"},
		{name: "DoQ insecure", endpoint: "doq://resolver.example", insecure: true, transport: "QUIC (DoQ)", security: "encrypted, certificate verification disabled"},
		{name: "DoH insecure", endpoint: "https://resolver.example/dns-query", insecure: true, transport: "HTTPS (DoH)", security: "encrypted, certificate verification disabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := resolver.ParseEndpoint(tt.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &Config{Endpoint: ep, Insecure: tt.insecure}
			if got := inspectionTransport(cfg, ep.URL()); got != tt.transport {
				t.Errorf("inspectionTransport() = %q, want %q", got, tt.transport)
			}
			if got := displaySecurity(resolverTransportSecurity(cfg, ep.URL())); got != tt.security {
				t.Errorf("resolver transport security = %q, want %q", got, tt.security)
			}
		})
	}
}

func TestResolverTransportSecuritySupportsLegacyResolverURLs(t *testing.T) {
	tests := []struct {
		name     string
		scheme   string
		security string
	}{
		{name: "UDP", scheme: "", security: "plaintext"},
		{name: "TCP", scheme: "tcp", security: "plaintext"},
		{name: "DoT", scheme: "tls", security: "verified TLS"},
		{name: "DoT alias", scheme: "dot", security: "verified TLS"},
		{name: "DoQ", scheme: "quic", security: "verified TLS"},
		{name: "DoQ alias", scheme: "doq", security: "verified TLS"},
		{name: "DoH", scheme: "https", security: "verified TLS"},
		{name: "HTTP", scheme: "http", security: "plaintext"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := mustURL(t, "//resolver.example:53")
			server.Scheme = tt.scheme
			cfg := &Config{Insecure: tt.name == "HTTP"}
			if got := displaySecurity(resolverTransportSecurity(cfg, server)); got != tt.security {
				t.Errorf("resolver transport security = %q, want %q", got, tt.security)
			}
		})
	}
}

func TestResolverTransportSecurityReportsPlatformResolver(t *testing.T) {
	if got, want := displaySecurity(resolverTransportSecurity(&Config{}, nil)), "OS-managed / unknown to fetch"; got != want {
		t.Fatalf("platform resolver security = %q, want %q", got, want)
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
		"\u2514\u2500 alias.example.com. → 192.0.2.1 (TTL 1m)",
		"\u2514\u2500 example.com. → 2001:db8::1 (TTL 5m)",
		"example.com. → alias.example.com. (TTL 2m)",
		`example.com. → "v=spf1 -all" (TTL 3m)`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestLookupDOHJSONPreservesTypedRecordData(t *testing.T) {
	answers := map[string]string{
		"NS":  `{"Status":0,"Answer":[{"name":"example.com.","type":2,"TTL":60,"data":"ns1.example.com."}]}`,
		"TXT": `{"Status":0,"Answer":[{"name":"example.com.","type":16,"TTL":60,"data":"\"first\" \" second\" \"\""}]}`,
		"MX":  `{"Status":0,"Answer":[{"name":"example.com.","type":15,"TTL":60,"data":"10 mail.example.com."}]}`,
		"SOA": `{"Status":0,"Answer":[{"name":"example.com.","type":6,"TTL":60,"data":"ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300"}]}`,
		"SRV": `{"Status":0,"Answer":[{"name":"example.com.","type":33,"TTL":60,"data":"10 5 443 service.example.com."}]}`,
		"CAA": `{"Status":0,"Answer":[{"name":"example.com.","type":257,"TTL":60,"data":"0 issue \"letsencrypt.org\""}]}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		if answer, ok := answers[r.URL.Query().Get("type")]; ok {
			io.WriteString(w, answer)
			return
		}
		io.WriteString(w, `{"Status":0}`)
	}))
	defer server.Close()

	res, err := lookup(context.Background(), &Config{DNSServer: mustURL(t, server.URL+"/dns-query")}, "example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := res.records["NS"][0].target; got != "ns1.example.com." {
		t.Fatalf("NS target = %q", got)
	}
	if got := res.records["TXT"][0].txt; len(got) != 3 || string(got[0]) != "first" || string(got[1]) != " second" || len(got[2]) != 0 {
		t.Fatalf("TXT chunks = %#v", got)
	}
	if got := res.records["MX"][0]; got.preference != 10 || got.target != "mail.example.com." {
		t.Fatalf("MX data = %#v", got)
	}
	if got := res.records["SOA"][0]; got.target != "ns1.example.com." || got.target2 != "hostmaster.example.com." || got.soa != [5]uint32{1, 3600, 600, 604800, 300} {
		t.Fatalf("SOA data = %#v", got)
	}
	if got := res.records["SRV"][0]; got.priority != 10 || got.weight != 5 || got.port != 443 || got.target != "service.example.com." {
		t.Fatalf("SRV data = %#v", got)
	}
	if got := formatCAA(res.records["CAA"][0].rawRData); got != `0 issue "letsencrypt.org"` {
		t.Fatalf("CAA data = %q", got)
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
	if got, want := cnames[0].owner, "example.com."; got != want {
		t.Fatalf("CNAME owner = %q, want %q", got, want)
	}
	if got, want := cnames[0].ttl, uint32(119); got != want {
		t.Fatalf("CNAME TTL = %d, want lowest TTL %d", got, want)
	}
}

func TestAggregateDeduplicatesRecordsByOwnerTypeAndValue(t *testing.T) {
	out := &result{records: make(map[string][]record)}
	results := []queryResult{{
		typ: inspectTypes[0],
		records: []record{
			{owner: "first.example.", typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.1"), ttl: 120, hasTTL: true},
			{owner: "second.example.", typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.1"), ttl: 90, hasTTL: true},
			{owner: "FIRST.EXAMPLE.", typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.1"), ttl: 60, hasTTL: true},
		},
	}}

	aggregate(out, results, time.Now())
	records := out.records["A"]
	if got, want := len(records), 2; got != want {
		t.Fatalf("A records = %#v, want %d owner-distinct records", records, want)
	}
	if got, want := records[0].ttl, uint32(60); got != want {
		t.Fatalf("duplicate same-owner TTL = %d, want lowest TTL %d", got, want)
	}
	if got, want := records[1].owner, "second.example."; got != want {
		t.Fatalf("second owner = %q, want %q", got, want)
	}
}

func TestRecordOwnersUseCanonicalFQDNPresentation(t *testing.T) {
	owner, err := resolver.ParseName("WWW.Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := recordFromWire(resolver.Record{
		Owner:      owner,
		Type:       uint16(dnsmessage.TypeA),
		TTLPresent: true,
		RData:      []byte{192, 0, 2, 1},
	})
	if !ok {
		t.Fatal("recordFromWire() rejected an A record")
	}
	if got, want := rec.owner, "www.example.com."; got != want {
		t.Fatalf("direct DNS owner = %q, want %q", got, want)
	}
	if got, want := normalizedOwner("WWW.Example.COM"), rec.owner; got != want {
		t.Fatalf("platform owner = %q, want direct DNS owner %q", got, want)
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
	if got, want := records[0].owner, "example.com."; got != want {
		t.Fatalf("owner = %q, want %q", got, want)
	}
	if got, want := records[0].address.String(), "192.0.2.10"; got != want {
		t.Fatalf("value = %q, want %q", got, want)
	}
	if got, want := records[0].source, recordSourceDNS; got != want {
		t.Fatalf("source = %d, want direct DNS source %d", got, want)
	}
	if got, want := records[0].ttl, uint32(42); got != want {
		t.Fatalf("TTL = %d, want %d", got, want)
	}
}

func TestLookupUDPRecordsPreservesTXTChunks(t *testing.T) {
	addr, stop := startUDPServerWithAnswers(t, func(question dnsmessage.Question) []dnsmessage.Resource {
		if question.Type != dnsmessage.TypeTXT {
			return nil
		}
		return []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  question.Name,
				Type:  dnsmessage.TypeTXT,
				Class: dnsmessage.ClassINET,
				TTL:   300,
			},
			Body: &dnsmessage.TXTResource{TXT: []string{"first", " second", ""}},
		}}
	})
	defer stop()

	records, err := lookupUDPRecords(context.Background(), addr, "example.com", queryType{
		label:   "TXT",
		dohType: "TXT",
		dnsType: dnsmessage.TypeTXT,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want one TXT record", len(records))
	}
	got := records[0].txt
	if len(got) != 3 || string(got[0]) != "first" || string(got[1]) != " second" || len(got[2]) != 0 {
		t.Fatalf("TXT chunks = %#v, want preserved boundaries", got)
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
	if res.resolver != "platform resolver" {
		t.Fatalf("resolver label = %q, want platform resolver", res.resolver)
	}
	if res.transport != "platform resolver" || res.source != "platform resolver" {
		t.Fatalf("platform summary = transport %q, source %q", res.transport, res.source)
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
	if got, want := res.records["A"][0].address.String(), "192.0.2.44"; got != want {
		t.Fatalf("A record = %q, want %q", got, want)
	}
	if got, want := res.records["AAAA"][0].address.String(), "2001:db8::44"; got != want {
		t.Fatalf("AAAA record = %q, want %q", got, want)
	}
	if res.records["A"][0].hasTTL || res.records["AAAA"][0].hasTTL {
		t.Fatalf("default resolver records unexpectedly reported TTLs: %#v", res.records)
	}
	for _, typ := range []string{"A", "AAAA"} {
		if got, want := res.records[typ][0].owner, "example.com."; got != want {
			t.Fatalf("%s owner = %q, want %q", typ, got, want)
		}
		if got, want := res.records[typ][0].source, recordSourcePlatform; got != want {
			t.Fatalf("%s source = %d, want platform source %d", typ, got, want)
		}
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
	if res.platformFallback {
		t.Fatal("platformFallback = true for a direct nameserver query")
	}
	if got := len(res.records["A"]); got != 1 {
		t.Fatalf("A records = %d, want 1", got)
	}
	if got, want := res.records["A"][0].address.String(), "192.0.2.10"; got != want {
		t.Fatalf("A value = %q, want %q", got, want)
	}
	if got, want := res.records["A"][0].ttl, uint32(42); got != want {
		t.Fatalf("A TTL = %d, want %d", got, want)
	}
}

func TestLookupSystemCombinesDirectRecordsWithPlatformAddresses(t *testing.T) {
	origDefaultLookupIPAddr := defaultLookupIPAddr
	t.Cleanup(func() {
		defaultLookupIPAddr = origDefaultLookupIPAddr
	})
	defaultLookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.42")}}, nil
	}

	addr, stop := startUDPServerWithAnswers(t, func(question dnsmessage.Question) []dnsmessage.Resource {
		if question.Type != dnsmessage.TypeTXT {
			return nil
		}
		return []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  question.Name,
				Type:  dnsmessage.TypeTXT,
				Class: dnsmessage.ClassINET,
				TTL:   120,
			},
			Body: &dnsmessage.TXTResource{TXT: []string{"device=printer"}},
		}}
	})
	defer stop()

	res, err := lookup(context.Background(), &Config{SystemPolicy: &resolver.SystemResolverPolicy{
		Nameservers: []string{addr},
		Attempts:    1,
		Timeout:     time.Second,
	}}, "printer.local", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !res.platformFallback {
		t.Fatal("platformFallback = false, want mixed lookup")
	}
	if got, want := res.records["TXT"][0].source, recordSourceDNS; got != want {
		t.Fatalf("TXT source = %d, want direct DNS source %d", got, want)
	}
	if got, want := res.records["TXT"][0].ttl, uint32(120); got != want || !res.records["TXT"][0].hasTTL {
		t.Fatalf("TXT TTL = %d (present %t), want %d", got, res.records["TXT"][0].hasTTL, want)
	}
	if got, want := res.records["A"][0].source, recordSourcePlatform; got != want {
		t.Fatalf("A source = %d, want platform source %d", got, want)
	}
	if res.records["A"][0].hasTTL {
		t.Fatal("platform A record unexpectedly has a TTL")
	}

	p := core.TestPrinter(false)
	render(p, res)
	out := string(p.Bytes())
	for _, want := range []string{
		"Resolver: system nameservers + platform resolver",
		"Fallback: platform resolver used for addresses",
		"192.0.2.42 (platform resolver; TTL unavailable)",
		`"device=printer" (TTL 2m)`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("mixed lookup output missing %q:\n%s", want, out)
		}
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
	if res.resolver != "system nameservers + platform resolver" {
		t.Fatalf("resolver label = %q, want mixed resolver summary", res.resolver)
	}
	if !res.platformFallback {
		t.Fatal("platformFallback = false for platform fallback")
	}
	if res.transport != "mixed" || res.security != "mixed" {
		t.Fatalf("mixed summary = transport %q, security %q", res.transport, res.security)
	}
	if got := len(res.records["A"]); got != 1 {
		t.Fatalf("A records = %d, want 1", got)
	}
	if got, want := res.records["A"][0].address.String(), "192.0.2.99"; got != want {
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
			"A": {{typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.1"), hasTTL: true, ttl: 60}},
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

func TestRenderShowsRecordOwner(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host: "www.example.com",
		records: map[string][]record{
			"CNAME": {{owner: "www.example.com.", typ: dnsmessage.TypeCNAME, target: "cdn.example.net.", ttl: 300, hasTTL: true}},
		},
	})

	if out := string(p.Bytes()); !strings.Contains(out, "www.example.com. → cdn.example.net. (TTL 5m)") {
		t.Fatalf("output missing record owner and target:\n%s", out)
	}
}

func TestRenderShowsUnavailableTTLPerRecord(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host:     "example.com",
		resolver: "system",
		records: map[string][]record{
			"A": {{typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.1"), ttl: 60, hasTTL: true}},
		},
	})

	out := string(p.Bytes())
	if !strings.Contains(out, "\u2514\u2500 192.0.2.1 (TTL 1m)") {
		t.Fatalf("output missing tree-formatted TTL:\n%s", out)
	}
}

func TestRenderShowsPlatformSourceAndUnavailableTTLOnRecord(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host: "printer.local",
		records: map[string][]record{
			"A": {{
				owner:   "printer.local.",
				typ:     dnsmessage.TypeA,
				address: net.ParseIP("192.0.2.1"),
				source:  recordSourcePlatform,
			}},
		},
	})

	if out := string(p.Bytes()); !strings.Contains(out, "printer.local. → 192.0.2.1 (platform resolver; TTL unavailable)") {
		t.Fatalf("output missing platform provenance and unavailable TTL:\n%s", out)
	}
}

func TestRenderMixedResolverSummaryAndPerRecordProvenance(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host:             "printer.local",
		resolver:         "system nameservers + platform resolver",
		transport:        "mixed",
		security:         "mixed",
		source:           "system resolver configuration + platform resolver",
		platformFallback: true,
		records: map[string][]record{
			"A": {{
				owner:   "printer.local.",
				typ:     dnsmessage.TypeA,
				address: net.ParseIP("192.0.2.1"),
				source:  recordSourcePlatform,
			}},
			"TXT": {{
				owner:  "printer.local.",
				typ:    dnsmessage.TypeTXT,
				txt:    [][]byte{[]byte("device=printer")},
				ttl:    120,
				hasTTL: true,
				source: recordSourceDNS,
			}},
		},
	})

	out := string(p.Bytes())
	for _, want := range []string{
		"Resolver: system nameservers + platform resolver",
		"Transport: mixed",
		"Transport security: mixed",
		"Fallback: platform resolver used for addresses",
		"192.0.2.1 (platform resolver; TTL unavailable)",
		`"device=printer" (TTL 2m)`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("mixed output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "device=printer (platform resolver") {
		t.Fatalf("direct record incorrectly marked as platform data:\n%s", out)
	}
}

func TestRenderSortsRecordsWithinType(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host:     "example.com",
		resolver: "system",
		records: map[string][]record{
			"A": {
				{typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.20"), ttl: 60, hasTTL: true},
				{typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.10"), ttl: 60, hasTTL: true},
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

func TestRecordFromWirePreservesTypedDNSData(t *testing.T) {
	owner, err := resolver.ParseName("example.com.")
	if err != nil {
		t.Fatal(err)
	}
	target, err := resolver.ParseName("service.example.net.")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := resolver.ParseName("hostmaster.example.com.")
	if err != nil {
		t.Fatal(err)
	}

	input := resolver.Record{
		Owner:      owner,
		Type:       uint16(dnsmessage.TypeSOA),
		TTL:        300,
		TTLPresent: true,
		Target:     &target,
		Target2:    &mailbox,
		Preference: 10,
		Priority:   20,
		Weight:     30,
		Port:       443,
		SOAValues:  [5]uint32{1, 2, 3, 4, 5},
		TXT:        [][]byte{[]byte("first"), []byte("second")},
		Params:     []resolver.SVCParam{{Key: uint16(dnsmessage.SVCParamALPN), Value: []byte{2, 'h', '2'}}},
		RData:      []byte{0xde, 0xad},
	}
	rec, ok := recordFromWire(input)
	if !ok {
		t.Fatal("recordFromWire() rejected a valid record")
	}
	input.TXT[0][0] = 'X'
	input.Params[0].Value[1] = 'X'
	input.RData[0] = 0

	if rec.typ != dnsmessage.TypeSOA || rec.owner != "example.com." || rec.target != "service.example.net." || rec.target2 != "hostmaster.example.com." {
		t.Fatalf("record identity and targets were not preserved: %#v", rec)
	}
	if rec.preference != 10 || rec.priority != 20 || rec.weight != 30 || rec.port != 443 || rec.soa != [5]uint32{1, 2, 3, 4, 5} {
		t.Fatalf("numeric DNS fields were not preserved: %#v", rec)
	}
	if got := string(rec.txt[0]); got != "first" {
		t.Fatalf("TXT data aliases resolver storage: %q", got)
	}
	if got := string(rec.params[0].Value); got != "\x02h2" {
		t.Fatalf("SVCB parameter aliases resolver storage: %q", got)
	}
	if got := hex.EncodeToString(rec.rawRData); got != "dead" {
		t.Fatalf("raw RDATA aliases resolver storage: %q", got)
	}
}

func TestWireNameTargetsRemainEscapedInTypedRecords(t *testing.T) {
	target, err := resolver.ParseName(`bad\010dot\046slash\092.example.`)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := target.Wire()
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := resolver.ParseName("hostmaster.example.")
	if err != nil {
		t.Fatal(err)
	}
	mailboxWire, err := mailbox.Wire()
	if err != nil {
		t.Fatal(err)
	}

	records := []resolver.Record{
		{Type: uint16(dnsmessage.TypeNS), Target: &target, RData: wire},
		{Type: uint16(dnsmessage.TypeMX), Target: &target, RData: append([]byte{0, 10}, wire...)},
		{Type: uint16(dnsmessage.TypeSOA), Target: &target, Target2: &mailbox, RData: append(append(append([]byte(nil), wire...), mailboxWire...), make([]byte, 20)...)},
		{Type: uint16(dnsmessage.TypeSRV), Target: &target, RData: append(make([]byte, 6), wire...)},
	}
	for _, input := range records {
		rec, ok := recordFromWire(input)
		if !ok {
			t.Fatalf("recordFromWire() rejected type %d", input.Type)
		}
		if rec.target != target.String() {
			t.Errorf("type %d target = %q, want escaped %q", input.Type, rec.target, target.String())
		}
		if strings.ContainsAny(rec.target, "\n\r") {
			t.Errorf("type %d target contains a raw line break: %q", input.Type, rec.target)
		}
	}
}

func TestRenderUsesTypedDNSRecordData(t *testing.T) {
	p := core.TestPrinter(false)
	records := map[string][]record{
		"A":     {{typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.1")}},
		"AAAA":  {{typ: dnsmessage.TypeAAAA, address: net.ParseIP("2001:db8::1")}},
		"CNAME": {{typ: dnsmessage.TypeCNAME, target: "alias.example."}},
		"TXT":   {{typ: dnsmessage.TypeTXT, txt: [][]byte{[]byte("first"), []byte("second")}}},
		"MX":    {{typ: dnsmessage.TypeMX, preference: 10, target: "mail.example."}},
		"NS":    {{typ: dnsmessage.TypeNS, target: "ns1.example."}},
		"SOA": {{
			typ: dnsmessage.TypeSOA, target: "ns1.example.", target2: "hostmaster.example.",
			soa: [5]uint32{2026082901, 3600, 600, 604800, 300},
		}},
		"SRV":  {{typ: dnsmessage.TypeSRV, priority: 10, weight: 5, port: 443, target: "service.example."}},
		"CAA":  {{typ: dnsTypeCAA, rawRData: append([]byte{0, 5}, []byte("issueletsencrypt.org")...)}},
		"SVCB": {{typ: dnsmessage.TypeSVCB, priority: 0, target: "."}},
		"HTTPS": {{
			typ: dnsmessage.TypeHTTPS, priority: 1, target: ".",
			params: []resolver.SVCParam{{Key: uint16(dnsmessage.SVCParamALPN), Value: []byte{2, 'h', '2'}}},
		}},
		"TYPE99": {{typ: dnsmessage.Type(99), rawRData: []byte{0xde, 0xad}}},
	}
	render(p, &result{host: "example.com", records: records})
	out := string(p.Bytes())
	for _, want := range []string{
		"192.0.2.1", "2001:db8::1", "alias.example.", "\"first\"\n", "\"second\"\n",
		"Priority: 10", "mail.example.", "ns1.example.",
		"Primary NS: ns1.example.", "Responsible: hostmaster.example.",
		"Serial: 2026082901", "Refresh: 1h", "Retry: 10m", "Expire: 1w", "Minimum TTL: 5m",
		"Weight: 5", "service.example.:443",
		"Flags: 0", "Tag: issue", "Value: letsencrypt.org", "priority 0 → .", "priority 1 → .", "ALPN: h2",
		"TYPE99", "0xdead",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("typed record output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderComplexRecordsUseLabeledFields(t *testing.T) {
	p := core.TestPrinter(false)
	rawCAA := append([]byte{1, 5}, []byte("issueacme.org")...)
	render(p, &result{host: "example.com", records: map[string][]record{
		"MX": {{
			owner: "example.com.", typ: dnsmessage.TypeMX, preference: 10,
			target: "mail.example.com.", ttl: 3600, hasTTL: true,
		}},
		"SRV": {{
			owner: "_https._tcp.example.com.", typ: dnsmessage.TypeSRV,
			priority: 20, weight: 5, port: 443, target: "service.example.com.",
			ttl: 300, hasTTL: true,
		}},
		"SOA": {{
			owner: "example.com.", typ: dnsmessage.TypeSOA,
			target: "ns1.example.com.", target2: "hostmaster.example.com.",
			soa: [5]uint32{2026082901, 3600, 600, 604800, 300}, ttl: 3600, hasTTL: true,
		}},
		"CAA": {{
			owner: "example.com.", typ: dnsTypeCAA, rawRData: rawCAA,
			ttl: 3600, hasTTL: true,
		}},
	}})

	out := string(p.Bytes())
	for _, want := range []string{
		"example.com. → mail.example.com.", "     Priority: 10", "     TTL: 1h",
		"_https._tcp.example.com. → service.example.com.:443", "     Weight: 5",
		"example.com.\n", "Primary NS: ns1.example.com.", "Responsible: hostmaster.example.com.",
		"Serial: 2026082901", "Refresh: 1h", "Retry: 10m", "Expire: 1w", "Minimum TTL: 5m",
		"Flags: 1", "Tag: issue", "Value: acme.org",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("complex record output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderComplexRecordTreeContinuationStopsAtLastRecord(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{host: "example.com", records: map[string][]record{
		"MX": {
			{typ: dnsmessage.TypeMX, preference: 2, target: "first.example."},
			{typ: dnsmessage.TypeMX, preference: 10, target: "last.example."},
		},
	}})

	out := string(p.Bytes())
	if !strings.Contains(out, "  │  Priority: 2") {
		t.Fatalf("non-final record details lost tree continuation:\n%s", out)
	}
	if strings.Contains(out, "  │  Priority: 10") || !strings.Contains(out, "     Priority: 10") {
		t.Fatalf("final record details retained tree continuation:\n%s", out)
	}
}

func TestAggregateKeepsDistinctDOHPresentationRecords(t *testing.T) {
	out := &result{records: make(map[string][]record)}
	results := []queryResult{
		{typ: inspectTypes[4], records: []record{
			{typ: dnsmessage.TypeMX, presentation: "10 first.example."},
			{typ: dnsmessage.TypeMX, presentation: "20 second.example."},
		}},
		{typ: inspectTypes[6], records: []record{
			{typ: dnsmessage.TypeSOA, presentation: "ns1.example. hostmaster.example. 1 2 3 4 5"},
			{typ: dnsmessage.TypeSOA, presentation: "ns2.example. hostmaster.example. 2 3 4 5 6"},
		}},
		{typ: inspectTypes[7], records: []record{
			{typ: dnsmessage.TypeSRV, presentation: "10 5 443 first.example."},
			{typ: dnsmessage.TypeSRV, presentation: "20 5 443 second.example."},
		}},
	}
	aggregate(out, results, time.Now())
	for _, typ := range []string{"MX", "SOA", "SRV"} {
		if got := len(out.records[typ]); got != 2 {
			t.Fatalf("%s records = %d, want 2 distinct DoH records: %#v", typ, got, out.records[typ])
		}
	}
}

func TestRenderTXTChunksAreQuotedAndCannotInjectLines(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{host: "example.com", records: map[string][]record{
		"TXT": {{typ: dnsmessage.TypeTXT, txt: [][]byte{[]byte("line\nnext"), {0x1b, '[', 'A'}}}},
	}})
	out := string(p.Bytes())
	for _, want := range []string{"\"line\\nnext\"\n", "\"\\x1b[A\"\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("TXT chunk was not safely quoted: missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, `"line\nnext" "\x1b[A"`) {
		t.Fatalf("TXT chunks were rendered as one space-joined value: %q", out)
	}
	if strings.Contains(out, "line\nnext") || strings.ContainsRune(out, '\x1b') {
		t.Fatalf("TXT data injected terminal layout or controls: %q", out)
	}
}

func TestRecordFromDOHRejectsMissingTXTDataButKeepsEmptyChunk(t *testing.T) {
	owner, err := resolver.ParseName("example.com.")
	if err != nil {
		t.Fatal(err)
	}
	answer := resolver.DOHRecord{Record: resolver.Record{Owner: owner, Type: uint16(dnsmessage.TypeTXT)}}
	if _, ok := recordFromDOH(answer); ok {
		t.Fatal("recordFromDOH() accepted a TXT answer with missing data")
	}
	answer.Data = `""`
	rec, ok := recordFromDOH(answer)
	if !ok || len(rec.txt) != 1 || len(rec.txt[0]) != 0 {
		t.Fatalf("empty TXT chunk was not preserved: %#v, %t", rec, ok)
	}
}

func TestDOHCAANumericTagIsParsedSemantically(t *testing.T) {
	rec := semanticRecord(resolver.Record{Type: uint16(dnsTypeCAA)}, `0 0 "value"`, false)
	if got := formatCAA(rec.rawRData); got != `0 0 "value"` {
		t.Fatalf("numeric CAA tag was not parsed: %q", got)
	}
}

func TestRenderEscapesCAAAndSVCBFields(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{host: "example.com", records: map[string][]record{
		"CAA": {{typ: dnsTypeCAA, rawRData: append([]byte{0, 8}, []byte("bad\nnamevalue")...)}},
		"HTTPS": {{
			typ: dnsmessage.TypeHTTPS, priority: 1, target: ".",
			params: []resolver.SVCParam{{Key: uint16(dnsmessage.SVCParamALPN), Value: []byte{8, 'b', 'a', 'd', '\n', 'n', 'a', 'm', 'e'}}},
		}},
	}})
	out := string(p.Bytes())
	for _, want := range []string{`"bad\nname"`, `ALPN: "bad\nname"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("record field was not escaped as %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "bad\nname") {
		t.Fatalf("record field injected an output line: %q", out)
	}
}

func TestRenderHTTPSExpandsServiceBindingParameters(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{host: "example.com", records: map[string][]record{
		"HTTPS": {{
			owner: "example.com.", typ: dnsmessage.TypeHTTPS, priority: 1, target: ".",
			params: []resolver.SVCParam{
				{Key: uint16(dnsmessage.SVCParamMandatory), Value: []byte{0, 1, 0, 4}},
				{Key: uint16(dnsmessage.SVCParamDOHPath), Value: []byte("/dns-query{?dns}")},
				{Key: uint16(dnsmessage.SVCParamECH), Value: []byte{1, 2, 3}},
				{Key: uint16(dnsmessage.SVCParamIPv6Hint), Value: net.ParseIP("2001:db8::1")},
				{Key: uint16(dnsmessage.SVCParamPort), Value: []byte{1, 0xbb}},
				{Key: uint16(dnsmessage.SVCParamIPv4Hint), Value: []byte{192, 0, 2, 1, 192, 0, 2, 2}},
				{Key: uint16(dnsmessage.SVCParamALPN), Value: []byte{2, 'h', '2', 2, 'h', '3'}},
				{Key: uint16(dnsmessage.SVCParamOHTTP)},
				{Key: uint16(dnsmessage.SVCParamTLSSupportedGroups), Value: []byte{0, 23, 0, 29}},
				{Key: 10, Value: []byte{0xde, 0xad}},
			},
			ttl: 300, hasTTL: true,
		}},
	}})

	out := string(p.Bytes())
	for _, want := range []string{
		"example.com. priority 1 → .",
		"Mandatory: alpn, ipv4hint",
		"ALPN: h2, h3",
		"Port: 443",
		"IPv4 hints: 192.0.2.1, 192.0.2.2",
		"IPv6 hints: 2001:db8::1",
		"ECH: AQID",
		"DoH path: /dns-query{?dns}",
		"OHTTP: true",
		"TLS supported groups: 23, 29",
		"key10: 0xdead",
		"TTL: 5m",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTTPS output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ALPN=h2") || strings.Contains(out, "IPv4Hint=") {
		t.Fatalf("HTTPS parameters were flattened:\n%s", out)
	}
}

func TestRenderSVCBAliasModeAndMalformedParameters(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{host: "example.com", records: map[string][]record{
		"SVCB": {{
			owner: "example.com.", typ: dnsmessage.TypeSVCB, priority: 0, target: ".",
		}},
		"HTTPS": {{
			owner: "example.com.", typ: dnsmessage.TypeHTTPS, priority: 1, target: ".",
			params: []resolver.SVCParam{{Key: uint16(dnsmessage.SVCParamALPN), Value: []byte{3, 'h', '2'}}},
		}},
	}})

	out := string(p.Bytes())
	for _, want := range []string{
		"example.com. priority 0 → .",
		"Mode: AliasMode",
		"ALPN: 0x036832",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("SVCB output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderSVCBUnknownRawDataWhenMalformed(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{host: "example.com", records: map[string][]record{
		"HTTPS": {{
			owner: "example.com.", typ: dnsmessage.TypeHTTPS, priority: 1, target: ".",
			rawRData: []byte{0, 1, 1, 'x', 0, 9, 0, 4, 0xde},
		}},
	}})
	if out := string(p.Bytes()); !strings.Contains(out, "Raw RDATA: 0x0001017800090004de") {
		t.Fatalf("malformed HTTPS RDATA was not retained:\n%s", out)
	}
}

func TestRenderSortsTypedNumericFieldsNumerically(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{host: "example.com", records: map[string][]record{
		"MX": {
			{typ: dnsmessage.TypeMX, preference: 10, target: "ten.example."},
			{typ: dnsmessage.TypeMX, preference: 2, target: "two.example."},
		},
	}})
	out := string(p.Bytes())
	two := strings.Index(out, "two.example.")
	ten := strings.Index(out, "ten.example.")
	if two < 0 || ten < 0 || two > ten {
		t.Fatalf("MX records are not sorted by numeric preference:\n%s", out)
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
		{typ: inspectTypes[0], records: []record{{typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.1")}}},
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
	return startUDPServerWithAnswers(t, func(question dnsmessage.Question) []dnsmessage.Resource {
		if question.Type != dnsmessage.TypeA {
			return nil
		}
		return []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  question.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   42,
			},
			Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}},
		}}
	})
}

func startUDPServerWithAnswers(t *testing.T, answers func(dnsmessage.Question) []dnsmessage.Resource) (string, func()) {
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
			res.Answers = answers(req.Questions[0])
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
