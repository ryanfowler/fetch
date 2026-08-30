package dnsinspect

import (
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"

	"golang.org/x/net/dns/dnsmessage"
)

func TestRenderExtraVerboseIncludesResolverInternals(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host:                  "example.com",
		queryName:             "example.com",
		verbosity:             core.VExtraVerbose,
		configuredNameservers: []string{"192.0.2.53:53", "192.0.2.54:53"},
		resolverAttempts:      3,
		resolverTimeout:       2 * time.Second,
		resolverRotation:      "enabled",
		resolverConfiguration: "/etc/resolv.conf",
		resolverRouting:       "direct nameserver queries",
		resolverSearchDomains: "not applied",
		resolverOSRouting:     "not applied by direct queries",
		queries: []queryResult{{
			typ:       inspectTypes[0],
			status:    queryStatusNoData,
			responder: "192.0.2.54:53",
			transport: resolver.TransportUDP,
			duration:  4 * time.Millisecond,
			attempts:  2,
		}},
		records: map[string][]record{},
	})
	out := string(p.Bytes())
	for _, want := range []string{
		"System resolver",
		"Query name: example.com",
		"Configured nameservers: 192.0.2.53:53, 192.0.2.54:53",
		"Resolver attempts: 3 per nameserver",
		"Resolver timeout: 2s",
		"Resolver rotation: enabled",
		"Configuration: /etc/resolv.conf",
		"Routing: direct nameserver queries",
		"Search domains: not applied",
		"OS resolver routing: not applied by direct queries",
		"A: no data · UDP · 192.0.2.54:53 · 4ms · 2 attempts",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("extra verbose output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderQueryDetailsIncludesResponderMetadata(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host:      "example.com",
		verbosity: core.VExtraVerbose,
		queries: []queryResult{{
			typ:       inspectTypes[0],
			status:    queryStatusData,
			responder: "192.0.2.53:53",
			transport: resolver.TransportUDP,
			duration:  4 * time.Millisecond,
			attempts:  1,
			records:   []record{{typ: dnsmessage.TypeA}},
		}},
		records: map[string][]record{},
	})
	out := string(p.Bytes())
	for _, want := range []string{"A: 1 record · UDP · 192.0.2.53:53", "4ms", "1 attempt"} {
		if !strings.Contains(out, want) {
			t.Fatalf("query metadata missing %q:\n%s", want, out)
		}
	}
}

func TestRenderTCPFallbackAsTransportMetadata(t *testing.T) {
	res := &result{
		host:      "example.com",
		transport: "UDP",
		records:   make(map[string][]record),
	}
	aggregate(res, []queryResult{{
		typ:         inspectTypes[0],
		records:     []record{{typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.1")}},
		tcpFallback: true,
	}}, time.Now())

	p := core.TestPrinter(false)
	render(p, res)
	out := string(p.Bytes())
	if !strings.Contains(out, "Transport: UDP → TCP fallback") {
		t.Fatalf("fallback transport metadata missing:\n%s", out)
	}
	if strings.Contains(out, "warning:") || strings.Contains(out, "truncated") {
		t.Fatalf("fallback was rendered as a warning:\n%s", out)
	}
}

func TestAggregateFailedTCPFallbackRemainsFailure(t *testing.T) {
	res := &result{transport: "UDP", records: make(map[string][]record)}
	if err := aggregate(res, []queryResult{{
		typ:         inspectTypes[3],
		err:         errors.New("DNS TCP fallback: connection refused"),
		tcpFallback: true,
	}}, time.Now()); err == nil {
		t.Fatal("aggregate() error = nil, want failed TCP retry error")
	}
	if len(res.failures) != 1 || res.queries[0].status != queryStatusFailed {
		t.Fatalf("failed fallback result = %#v, want one failed query", res)
	}

	p := core.TestPrinter(false)
	render(p, res)
	out := string(p.Bytes())
	if !strings.Contains(out, "Status: incomplete — 1 of 1 queries failed") || !strings.Contains(out, "DNS TCP fallback: connection refused") {
		t.Fatalf("failed fallback was not rendered as a failure:\n%s", out)
	}
}

func TestRenderTCPFallbackDetailsAtExtraVerbose(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host:      "example.com",
		transport: "UDP",
		verbosity: core.VExtraVerbose,
		queries: []queryResult{
			{typ: inspectTypes[0], status: queryStatusData, records: []record{{typ: dnsmessage.TypeA}}, tcpFallback: true},
			{typ: inspectTypes[3], status: queryStatusNoData, tcpFallback: true},
		},
		records: map[string][]record{},
	})

	out := string(p.Bytes())
	for _, want := range []string{
		"Queries\n",
		"A: 1 record · UDP → TCP fallback",
		"TXT: no data · UDP → TCP fallback",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("verbose fallback details missing %q:\n%s", want, out)
		}
	}
}

func TestRenderWithoutTCPFallbackKeepsTransportUnchanged(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{
		host:      "example.com",
		transport: "UDP",
		records:   map[string][]record{},
	})

	out := string(p.Bytes())
	if !strings.Contains(out, "Transport: UDP\n") {
		t.Fatalf("transport changed without fallback:\n%s", out)
	}
	if strings.Contains(out, "TCP fallback") {
		t.Fatalf("output mentions fallback when none was used:\n%s", out)
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

func TestCompareRecordsUsesSemanticOrdering(t *testing.T) {
	caa := func(flags byte, tag, value string) []byte {
		return append([]byte{flags, byte(len(tag))}, append([]byte(tag), []byte(value)...)...)
	}
	tests := []struct {
		name string
		a    record
		b    record
	}{
		{name: "A numeric bytes", a: record{typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.2")}, b: record{typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.10")}},
		{name: "AAAA numeric bytes", a: record{typ: dnsmessage.TypeAAAA, address: net.ParseIP("2001:db8::2")}, b: record{typ: dnsmessage.TypeAAAA, address: net.ParseIP("2001:db8::10")}},
		{name: "CNAME canonical target", a: record{typ: dnsmessage.TypeCNAME, target: "a.example."}, b: record{typ: dnsmessage.TypeCNAME, target: "B.example."}},
		{name: "NS canonical target", a: record{typ: dnsmessage.TypeNS, target: "ns10.example."}, b: record{typ: dnsmessage.TypeNS, target: "ns2.example."}},
		{name: "MX preference", a: record{typ: dnsmessage.TypeMX, preference: 2, target: "z.example."}, b: record{typ: dnsmessage.TypeMX, preference: 10, target: "a.example."}},
		{name: "MX target", a: record{typ: dnsmessage.TypeMX, preference: 10, target: "a.example."}, b: record{typ: dnsmessage.TypeMX, preference: 10, target: "b.example."}},
		{name: "SRV priority", a: record{typ: dnsmessage.TypeSRV, priority: 2, weight: 10, port: 9000, target: "z.example."}, b: record{typ: dnsmessage.TypeSRV, priority: 10, target: "a.example."}},
		{name: "SRV weight", a: record{typ: dnsmessage.TypeSRV, priority: 10, weight: 2, port: 9000}, b: record{typ: dnsmessage.TypeSRV, priority: 10, weight: 10, port: 1}},
		{name: "SRV port", a: record{typ: dnsmessage.TypeSRV, priority: 10, weight: 10, port: 2}, b: record{typ: dnsmessage.TypeSRV, priority: 10, weight: 10, port: 10}},
		{name: "SRV target", a: record{typ: dnsmessage.TypeSRV, priority: 10, weight: 10, port: 443, target: "a.example."}, b: record{typ: dnsmessage.TypeSRV, priority: 10, weight: 10, port: 443, target: "b.example."}},
		{name: "CAA tag", a: record{typ: dnsTypeCAA, rawRData: caa(128, "a", "z")}, b: record{typ: dnsTypeCAA, rawRData: caa(0, "b", "a")}},
		{name: "CAA flags", a: record{typ: dnsTypeCAA, rawRData: caa(0, "issue", "z")}, b: record{typ: dnsTypeCAA, rawRData: caa(128, "issue", "a")}},
		{name: "CAA value", a: record{typ: dnsTypeCAA, rawRData: caa(0, "issue", "a")}, b: record{typ: dnsTypeCAA, rawRData: caa(0, "issue", "b")}},
		{name: "SVCB priority", a: record{typ: dnsmessage.TypeSVCB, priority: 2, target: "z.example."}, b: record{typ: dnsmessage.TypeSVCB, priority: 10, target: "a.example."}},
		{name: "HTTPS target", a: record{typ: dnsmessage.TypeHTTPS, priority: 1, target: "a.example."}, b: record{typ: dnsmessage.TypeHTTPS, priority: 1, target: "b.example."}},
		{name: "SVCB canonical params", a: record{typ: dnsmessage.TypeSVCB, priority: 1, target: ".", params: []resolver.SVCParam{{Key: 4, Value: []byte{1}}, {Key: 1, Value: []byte("h2")}}}, b: record{typ: dnsmessage.TypeSVCB, priority: 1, target: ".", params: []resolver.SVCParam{{Key: 1, Value: []byte("h2")}, {Key: 4, Value: []byte{2}}}}},
		{name: "TXT chunk bytes", a: record{typ: dnsmessage.TypeTXT, txt: [][]byte{[]byte("10"), []byte("tail")}}, b: record{typ: dnsmessage.TypeTXT, txt: [][]byte{[]byte("2")}}},
		{name: "SOA owner", a: record{typ: dnsmessage.TypeSOA, owner: "a.example."}, b: record{typ: dnsmessage.TypeSOA, owner: "b.example."}},
		{name: "unknown type", a: record{typ: dnsmessage.Type(65280), rawRData: []byte{2}}, b: record{typ: dnsmessage.Type(65280), rawRData: []byte{10}}},
		{name: "unknown type number", a: record{typ: dnsmessage.Type(65280), rawRData: []byte{255}}, b: record{typ: dnsmessage.Type(65281), rawRData: []byte{0}}},
		{name: "owner tie breaker", a: record{owner: "a.example.", typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.1")}, b: record{owner: "b.example.", typ: dnsmessage.TypeA, address: net.ParseIP("192.0.2.1")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := compareRecords(test.a, test.b); got >= 0 {
				t.Fatalf("compareRecords(a, b) = %d, want < 0", got)
			}
			if got := compareRecords(test.b, test.a); got <= 0 {
				t.Fatalf("compareRecords(b, a) = %d, want > 0", got)
			}
		})
	}
}

func TestSVCBParameterOrderIsCanonicalForDeduplication(t *testing.T) {
	a := record{typ: dnsmessage.TypeHTTPS, priority: 1, target: ".", params: []resolver.SVCParam{
		{Key: 4, Value: []byte{192, 0, 2, 1}},
		{Key: 1, Value: []byte{2, 'h', '2'}},
	}}
	b := record{typ: dnsmessage.TypeHTTPS, priority: 1, target: ".", params: []resolver.SVCParam{
		{Key: 1, Value: []byte{2, 'h', '2'}},
		{Key: 4, Value: []byte{192, 0, 2, 1}},
	}}
	if a.semanticKey() != b.semanticKey() {
		t.Fatalf("equivalent SVCB parameter sets have different semantic keys:\n%s\n%s", a.semanticKey(), b.semanticKey())
	}
}

func TestRenderSortsUnknownSectionsByNumericType(t *testing.T) {
	p := core.TestPrinter(false)
	render(p, &result{host: "example.com", records: map[string][]record{
		"TYPE100": {{typ: dnsmessage.Type(100), rawRData: []byte{1}}},
		"TYPE20":  {{typ: dnsmessage.Type(20), rawRData: []byte{1}}},
	}})
	out := string(p.Bytes())
	type20, type100 := strings.Index(out, "  TYPE20\n"), strings.Index(out, "  TYPE100\n")
	if type20 < 0 || type100 < 0 || type20 > type100 {
		t.Fatalf("unknown record sections are not sorted by numeric type:\n%s", out)
	}
}

func TestAggregatePreservesDistinctMalformedSVCBRData(t *testing.T) {
	makeRecord := func(tail byte) record {
		return semanticRecord(resolver.Record{
			Type:  uint16(dnsmessage.TypeHTTPS),
			RData: []byte{0, 1, 0, 0, 1, 0, 2, tail},
		}, "", true)
	}
	out := &result{records: make(map[string][]record)}
	aggregate(out, []queryResult{{typ: inspectTypes[10], records: []record{makeRecord(0xaa), makeRecord(0xbb)}}}, time.Now())
	if got := len(out.records["HTTPS"]); got != 2 {
		t.Fatalf("malformed HTTPS records = %d, want 2 distinct raw values: %#v", got, out.records["HTTPS"])
	}
}

func TestSemanticRecordCanonicalizesDNSTargetCase(t *testing.T) {
	upper, err := resolver.ParseName("MAIL.Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := resolver.ParseName("mail.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	a := semanticRecord(resolver.Record{Type: uint16(dnsmessage.TypeMX), Preference: 10, Target: &upper}, "", true)
	b := semanticRecord(resolver.Record{Type: uint16(dnsmessage.TypeMX), Preference: 10, Target: &lower}, "", true)
	if a.target != "mail.example.com." || b.target != a.target || a.semanticKey() != b.semanticKey() {
		t.Fatalf("target names were not canonicalized: %#v %#v", a, b)
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
