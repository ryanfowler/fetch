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

func TestDNSQueryHostNormalizesToAbsoluteName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{name: "ordinary hostname", want: "example.com."},
		{name: "IDN", want: "xn--mnich-kva.example."},
		{name: "trailing dot", want: "example.com."},
		{name: "service label", want: "_acme-challenge.example."},
		{name: "IDN after service label", want: "_acme-challenge.xn--mnich-kva.example."},
		{name: "root", want: "."},
	}
	inputs := []string{
		"example.com",
		"münich.example",
		"example.com.",
		"_acme-challenge.example",
		"_acme-challenge.münich.example",
		".",
	}
	for i, input := range inputs {
		t.Run(tests[i].name, func(t *testing.T) {
			got, err := dnsQueryHost(input)
			if err != nil {
				t.Fatal(err)
			}
			if got != tests[i].want {
				t.Fatalf("DNS query host = %q, want %q", got, tests[i].want)
			}
		})
	}
}

func TestDNSQueryHostRejectsInvalidNames(t *testing.T) {
	tests := []string{"", "example..com", strings.Repeat("a", 64) + ".example"}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := dnsQueryHost(input); err == nil {
				t.Fatalf("dnsQueryHost(%q) succeeded, want invalid-name error", input)
			}
		})
	}
}

func TestQueryNameDiffersOnlyForMeaningfulNormalization(t *testing.T) {
	tests := []struct {
		host, queryName string
		want            bool
	}{
		{host: "example.com", queryName: "example.com.", want: false},
		{host: "EXAMPLE.COM", queryName: "EXAMPLE.COM.", want: false},
		{host: "example.com.", queryName: "example.com.", want: false},
		{host: "internal-service", queryName: "internal-service.", want: true},
		{host: "münich.example", queryName: "xn--mnich-kva.example.", want: true},
		{host: ".", queryName: ".", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := queryNameDiffers(tt.host, tt.queryName); got != tt.want {
				t.Fatalf("queryNameDiffers(%q, %q) = %t, want %t", tt.host, tt.queryName, got, tt.want)
			}
		})
	}
}

func TestInspectNormalizesIDNForDNSQueries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		if got, want := r.URL.Query().Get("name"), "xn--mnich-kva.example."; got != want {
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
	out := string(p.Bytes())
	if !strings.Contains(out, "192.0.2.1") {
		t.Fatalf("output missing IDN A record:\n%s", p.Bytes())
	}
	if !strings.Contains(out, "Query name: xn--mnich-kva.example.") {
		t.Fatalf("output missing normalized query name:\n%s", out)
	}
}

func TestInspectIPLiteralSkipsLookup(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "IPv4", url: "http://127.0.0.1", want: "127.0.0.1"},
		{name: "IPv6", url: "http://[2001:db8::1]", want: "2001:db8::1"},
		{name: "scoped IPv6", url: "http://[fe80::1%25lo0]", want: "fe80::1%lo0"},
		{name: "scoped IPv6 with encoded zone percent", url: "http://[fe80::1%25en%25foo]", want: "fe80::1%en%foo"},
		{name: "scoped IPv4-mapped IPv6", url: "http://[::ffff:192.0.2.1%25lo0]", want: "::ffff:192.0.2.1%lo0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := core.TestPrinter(false)
			status := Inspect(context.Background(), p, &Config{URL: mustURL(t, tt.url)})
			if status != 0 {
				t.Fatalf("status = %d, want 0\n%s", status, p.Bytes())
			}
			out := string(p.Bytes())
			for _, want := range []string{
				"Lookup\n",
				"Name: " + tt.want,
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
		})
	}
}

func TestIsIPLiteral(t *testing.T) {
	for _, tt := range []struct {
		host string
		want bool
	}{
		{host: "127.0.0.1", want: true},
		{host: "2001:db8::1", want: true},
		{host: "fe80::1%lo0", want: true},
		{host: "fe80::1%en%foo", want: true},
		{host: "127.0.0.1%bad", want: false},
		{host: "::ffff:192.0.2.1%lo0", want: true},
		{host: "example.com", want: false},
		{host: "2001:db8::1%", want: false},
	} {
		if got := isIPLiteral(tt.host); got != tt.want {
			t.Errorf("isIPLiteral(%q) = %t, want %t", tt.host, got, tt.want)
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

	res, err := lookup(context.Background(), &Config{
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
	if got, want := len(res.queries), len(inspectTypes); got != want {
		t.Fatalf("query results = %d, want %d", got, want)
	}
	for _, query := range res.queries {
		if query.duration <= 0 {
			t.Errorf("%s query duration = %s, want positive duration", query.typ.label, query.duration)
		}
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

func TestPlatformResolverPreservesIPv6ZonesAndDeduplicatesAddresses(t *testing.T) {
	origDefaultLookupIPAddr := defaultLookupIPAddr
	t.Cleanup(func() {
		defaultLookupIPAddr = origDefaultLookupIPAddr
	})

	defaultLookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("192.0.2.44")},
			{IP: net.ParseIP("192.0.2.44")},
			{IP: net.ParseIP("fe80::1"), Zone: "en0"},
			{IP: net.ParseIP("fe80::1"), Zone: "en0"},
			{IP: net.ParseIP("fe80::1"), Zone: "en1"},
		}, nil
	}

	res, err := lookup(context.Background(), &Config{ResolvConfPath: emptyResolvConf(t)}, "printer.local", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(res.records["A"]), 1; got != want {
		t.Fatalf("A record count = %d, want %d", got, want)
	}
	if got, want := len(res.records["AAAA"]), 2; got != want {
		t.Fatalf("AAAA record count = %d, want %d", got, want)
	}

	p := core.TestPrinter(false)
	render(p, res)
	out := string(p.Bytes())
	for _, want := range []string{"fe80::1%en0", "fe80::1%en1"} {
		if strings.Count(out, want) != 1 {
			t.Fatalf("output count for %q = %d, want 1:\n%s", want, strings.Count(out, want), out)
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
		"Resolvers: " + addr + ", platform resolver",
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

func TestSystemResolverSummaryUsesActualResponders(t *testing.T) {
	res := &result{
		resolver: "configured-first:53",
		records:  make(map[string][]record),
	}
	aggregate(res, []queryResult{
		{typ: inspectTypes[0], responder: "192.0.2.2:53", transport: resolver.TransportUDP, records: []record{{typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.1")}}},
		{typ: inspectTypes[1], responder: "192.0.2.1:53", transport: resolver.TransportUDP, records: []record{{typ: dnsmessage.TypeAAAA, address: net.ParseIP("2001:db8::1")}}},
	}, time.Now())
	setSystemResponderSummary(res)

	p := core.TestPrinter(false)
	render(p, res)
	out := string(p.Bytes())
	if !strings.Contains(out, "Resolvers: 192.0.2.1:53, 192.0.2.2:53") {
		t.Fatalf("actual responder summary missing or unsorted:\n%s", out)
	}
	if strings.Contains(out, "Resolver: configured-first:53") {
		t.Fatalf("configured resolver placeholder was rendered:\n%s", out)
	}
}

func TestDNSInspectionVerboseParity(t *testing.T) {
	base := &result{
		host:      "example.com",
		queryName: "example.com",
		transport: "UDP",
		security:  string(resolver.SecurityPlaintext),
		records: map[string][]record{
			"A": {{owner: "example.com.", typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.1"), hasTTL: true, ttl: 60}},
		},
	}

	rendered := func(verbosity core.Verbosity) string {
		res := *base
		res.verbosity = verbosity
		p := core.TestPrinter(false)
		render(p, &res)
		return string(p.Bytes())
	}
	if normal, verbose := rendered(core.VNormal), rendered(core.VVerbose); normal != verbose {
		t.Fatalf("-v changed DNS inspection output:\nnormal:\n%s\nverbose:\n%s", normal, verbose)
	}
	if silent := rendered(core.VSilent); silent != rendered(core.VNormal) {
		t.Fatalf("silent mode changed structured DNS inspection output")
	}
}

func TestDirectSystemResolverCaveatsArePlatformSpecific(t *testing.T) {
	generic := directSystemResolverCaveats("linux")
	if generic.routing != "direct nameserver queries" || generic.searchDomains != "not applied" {
		t.Fatalf("generic resolver caveats = %#v", generic)
	}
	if generic.osRouting != "not applied by direct queries" || generic.platformRouting != "" {
		t.Fatalf("generic platform caveat = %#v", generic)
	}

	macOS := directSystemResolverCaveats("darwin")
	if macOS.osRouting != "" {
		t.Fatalf("macOS unexpectedly has generic OS caveat = %q", macOS.osRouting)
	}
	if want := "scoped/VPN/per-interface and /etc/resolver routing not applied"; macOS.platformRouting != want {
		t.Fatalf("macOS platform caveat = %q, want %q", macOS.platformRouting, want)
	}
}

func TestSetSystemResolverDetailsReportsDirectQueryCaveats(t *testing.T) {
	out := &result{}
	setSystemResolverDetails(out, resolver.SystemResolverPolicy{
		Nameservers:    []string{"192.0.2.53:53"},
		ResolvConfPath: "/etc/resolv.conf",
	})
	if out.resolverConfiguration != "/etc/resolv.conf" {
		t.Fatalf("configuration = %q, want /etc/resolv.conf", out.resolverConfiguration)
	}
	if out.resolverRouting != "direct nameserver queries" || out.resolverSearchDomains != "not applied" {
		t.Fatalf("direct resolver path = %#v", out)
	}
	if out.resolverOSRouting == "" && out.resolverPlatformRouting == "" {
		t.Fatalf("direct resolver caveat is missing: %#v", out)
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
