package dnsinspect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"
)

const dnsTypeCAA dnsmessage.Type = 257

var inspectTypes = []queryType{
	{label: "A", dohType: "A", dnsType: dnsmessage.TypeA},
	{label: "AAAA", dohType: "AAAA", dnsType: dnsmessage.TypeAAAA},
	{label: "CNAME", dohType: "CNAME", dnsType: dnsmessage.TypeCNAME},
	{label: "TXT", dohType: "TXT", dnsType: dnsmessage.TypeTXT},
	{label: "MX", dohType: "MX", dnsType: dnsmessage.TypeMX},
	{label: "NS", dohType: "NS", dnsType: dnsmessage.TypeNS},
	{label: "SOA", dohType: "SOA", dnsType: dnsmessage.TypeSOA},
	{label: "SRV", dohType: "SRV", dnsType: dnsmessage.TypeSRV},
	{label: "CAA", dohType: "CAA", dnsType: dnsTypeCAA},
	{label: "SVCB", dohType: "SVCB", dnsType: dnsmessage.TypeSVCB},
	{label: "HTTPS", dohType: "HTTPS", dnsType: dnsmessage.TypeHTTPS},
}

// Config holds the parameters needed to perform a DNS inspection.
type Config struct {
	// Endpoint is populated by CLI/config validation. DNSServer is retained
	// for direct test fixtures and older internal callers.
	Endpoint   *resolver.Endpoint
	DNSServer  *url.URL
	Proxy      *url.URL
	CACerts    []*x509.Certificate
	TLSConfig  *tls.Config
	ClientCert *tls.Certificate
	Insecure   bool
	TLSMin     uint16
	TLSMax     uint16
	Timeout    time.Duration
	URL        *url.URL
	Silent     bool

	// ResolvConfPath overrides the resolver configuration file consulted when
	// no --dns-server is set. An empty value uses the platform default
	// (/etc/resolv.conf on supported platforms). Tests use it to avoid
	// depending on the host's resolver configuration.
	ResolvConfPath string

	// SystemPolicy supplies the system resolver policy directly. When set it
	// takes precedence over ResolvConfPath. Production callers leave it nil so
	// the policy is loaded from the resolver configuration file; tests use it
	// to select a nameserver with an arbitrary port.
	SystemPolicy *resolver.SystemResolverPolicy
}

type queryType struct {
	label   string
	dohType string
	dnsType dnsmessage.Type
}

type record struct {
	typ    string
	value  string
	ttl    uint32
	hasTTL bool
}

type result struct {
	host           string
	queryName      string
	resolver       string
	transport      string
	security       string
	source         string
	records        map[string][]record
	queries        []queryResult
	failures       []queryFailure
	queryTotal     int
	queryWithData  int
	queryNoData    int
	duration       time.Duration
	tcpFallback    bool
	ttlUnavailable bool
	silent         bool
}

type queryStatus uint8

const (
	queryStatusData queryStatus = iota
	queryStatusNoData
	queryStatusFailed
)

type queryResult struct {
	typ         queryType
	status      queryStatus
	records     []record
	err         error
	tcpFallback bool
}

type queryFailure struct {
	label string
	err   error
}

type resolverTargetInfo struct {
	label      string
	udpAddr    string
	useDefault bool
}

var defaultLookupIPAddr = net.DefaultResolver.LookupIPAddr

// systemResolvConfPath is the resolver configuration file used when no
// --dns-server is set. It is a variable so tests can point it at a fixture.
// Windows has no portable resolv.conf to enumerate.
var systemResolvConfPath = func() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/etc/resolv.conf"
}

// loadSystemResolverPolicy reads the system resolver policy. It returns nil
// when the file is unavailable or lists no nameservers.
func loadSystemResolverPolicy(cfg *Config) *resolver.SystemResolverPolicy {
	if cfg.SystemPolicy != nil {
		return cfg.SystemPolicy
	}
	path := cfg.ResolvConfPath
	if path == "" {
		path = systemResolvConfPath()
	}
	if path == "" {
		return nil
	}
	policy, err := resolver.LoadSystemResolverPolicy(path)
	if err != nil {
		return nil
	}
	return &policy
}

// Inspect resolves the configured URL hostname and renders DNS information to
// the printer. It returns a non-zero exit code on failure.
func Inspect(ctx context.Context, p *core.Printer, cfg *Config) int {
	return InspectWithError(ctx, p, p, cfg)
}

// InspectWithError resolves the configured URL hostname, writes the inspection
// result to output, and writes setup errors to errorOutput. It returns a
// non-zero exit code on failure. Keeping these streams separate lets callers
// pipe a successful inspection without also receiving diagnostics.
func InspectWithError(ctx context.Context, output, errorOutput *core.Printer, cfg *Config) int {
	host := cfg.URL.Hostname()
	if host == "" {
		writeDNSError(errorOutput, errors.New("--inspect-dns requires a hostname"))
		return 1
	}

	// DNS inspection is a diagnostic operation, so it must not leave one
	// stalled resolver query hanging forever. All record-type queries share
	// this single deadline, including resolver endpoint bootstrap.
	inspectionTimeout := cfg.Timeout
	if inspectionTimeout <= 0 {
		inspectionTimeout = core.DefaultDOHTimeout
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, inspectionTimeout)
	defer cancel()

	start := time.Now()
	if net.ParseIP(host) != nil {
		renderIPLiteral(output, host)
		return flushInspectionOutput(output, errorOutput)
	}

	res, err := lookup(ctx, cfg, host, start)
	if err != nil {
		writeDNSError(errorOutput, err)
		return 1
	}
	renderWithWarning(output, errorOutput, res)
	partial := len(res.failures) > 0
	if flushInspectionOutput(output, errorOutput) != 0 {
		return 1
	}
	if partial {
		return 1
	}
	return 0
}

func lookup(ctx context.Context, cfg *Config, host string, start time.Time) (*result, error) {
	server := cfg.DNSServer
	if cfg.Endpoint != nil {
		server = cfg.Endpoint.URL()
	}
	target := resolverTarget(server)
	out := &result{
		host:      host,
		resolver:  target.label,
		transport: inspectionTransport(cfg, server),
		security:  resolverSecurity(cfg, server),
		source:    inspectionSource(server),
		records:   make(map[string][]record),
		silent:    cfg.Silent,
	}

	// A missing --dns-server prefers the resolv.conf nameservers, which expose
	// every record type and per-record TTLs. The platform API is only the
	// fallback: it surfaces A/AAAA and no per-record TTLs.
	systemDefault := server == nil
	var systemPolicy *resolver.SystemResolverPolicy
	if systemDefault {
		policy := loadSystemResolverPolicy(cfg)
		if policy != nil && len(policy.Nameservers) > 0 {
			ordered := resolver.RotateSystemResolverPolicy(*policy)
			systemPolicy = &ordered
			target = resolverTargetInfo{label: ordered.Nameservers[0], udpAddr: ordered.Nameservers[0]}
			out.resolver = target.label
			out.transport = "UDP"
			out.security = string(resolver.SecurityPlaintext)
			out.source = "system resolver configuration"
		} else {
			systemPolicy = nil
			target = resolverTargetInfo{label: "system resolver", useDefault: true}
			out.resolver = target.label
			out.transport = "platform resolver"
			out.security = "platform resolver (OS-managed security)"
			out.source = "platform resolver"
			out.ttlUnavailable = true
		}
	}

	if cfg.Endpoint != nil && cfg.Endpoint.Transport != resolver.TransportUDP && cfg.Endpoint.Transport != resolver.TransportTCP && cfg.Endpoint.Transport != resolver.TransportTLS && cfg.Endpoint.Transport != resolver.TransportQUIC && cfg.Endpoint.Transport != resolver.TransportHTTPS {
		return nil, fmt.Errorf("resolver transport %s is not implemented", cfg.Endpoint.Transport)
	}

	// No usable system policy: fall back to the platform resolver (A/AAAA only).
	if target.useDefault {
		return platformLookup(ctx, out, host, start)
	}

	var streamClient *resolver.StreamClient
	var doqClient *resolver.DoQClient
	var dohClient *resolver.DOHClient
	var err error
	if cfg.Endpoint != nil && (cfg.Endpoint.Transport == resolver.TransportTCP || cfg.Endpoint.Transport == resolver.TransportTLS) {
		streamClient, err = resolver.NewStreamClient(ctx, resolver.StreamConfig{
			Endpoint:   cfg.Endpoint,
			TLSConfig:  cfg.TLSConfig,
			CACerts:    cfg.CACerts,
			ClientCert: cfg.ClientCert,
			Insecure:   cfg.Insecure,
			TLSMin:     cfg.TLSMin,
			TLSMax:     cfg.TLSMax,
		})
		if err != nil {
			return nil, fmt.Errorf("connect to resolver: %w", err)
		}
		defer streamClient.Close()
	}
	if cfg.Endpoint != nil && cfg.Endpoint.Transport == resolver.TransportQUIC {
		doqClient, err = resolver.NewDoQClient(ctx, resolver.DoQConfig{
			Endpoint:   cfg.Endpoint,
			TLSConfig:  cfg.TLSConfig,
			CACerts:    cfg.CACerts,
			ClientCert: cfg.ClientCert,
			Insecure:   cfg.Insecure,
			TLSMin:     cfg.TLSMin,
			TLSMax:     cfg.TLSMax,
		})
		if err != nil {
			return nil, fmt.Errorf("connect to resolver: %w", err)
		}
		defer doqClient.Close()
	}
	if server != nil && server.Scheme != "" && streamClient == nil && doqClient == nil {
		proxy := client.ProxyFunc(cfg.Proxy)
		dohClient, err = resolver.NewDOHClient(resolver.DOHConfig{
			Endpoint:   cfg.Endpoint,
			ServerURL:  server,
			Proxy:      proxy,
			TLSConfig:  cfg.TLSConfig,
			CACerts:    cfg.CACerts,
			ClientCert: cfg.ClientCert,
			Insecure:   cfg.Insecure,
			TLSMin:     cfg.TLSMin,
			TLSMax:     cfg.TLSMax,
			Timeout:    cfg.Timeout,
		})
		if err != nil {
			return nil, fmt.Errorf("connect to resolver: %w", err)
		}
		defer dohClient.Close()
	}

	queryHost, err := dnsQueryHost(host)
	if err != nil {
		return nil, fmt.Errorf("normalize hostname %s: %w", host, err)
	}
	out.queryName = queryHost
	queryCtx, cancelQuery := contextForDirectLookup(ctx, systemPolicy != nil)
	defer cancelQuery()
	results := runFanOut(queryCtx, queryHost, target, systemPolicy, streamClient, doqClient, dohClient)
	firstResult := aggregate(out, results, start)
	if systemPolicy != nil && (len(out.failures) > 0 || len(systemPolicy.Nameservers) > 1) {
		// Different record types can come from different configured servers.
		// With more than one server, the query layer may fail over silently,
		// so do not claim one server supplied the complete result.
		out.resolver = "system resolver (configured nameservers)"
	}

	// A system-nameserver query that returned no address records (for example a
	// .local/mDNS or a host resolved only via NSS or the hosts file) falls back
	// to the OS resolver so those names still resolve. Keep the original query
	// context for this operation; contextForDirectLookup reserves time for it.
	if systemPolicy != nil && !hasAddressRecords(out) {
		if platformAddrs, err := lookupDefaultResolverRecords(ctx, host); err == nil && len(platformAddrs) > 0 {
			return platformResult(out, platformAddrs, start), nil
		}
	}

	if recordCount(out) > 0 || len(out.failures) > 0 || out.queryTotal > 0 {
		return out, nil
	}
	if firstResult != nil {
		return nil, fmt.Errorf("lookup %s: %w", host, firstResult)
	}
	return nil, fmt.Errorf("lookup %s: no DNS records found", host)
}

// runFanOut queries every inspection record type concurrently. Exactly one
// backend is active: the system policy nameservers, or the selected stream,
// DoQ, DoH, or UDP resolver.
func runFanOut(ctx context.Context, host string, target resolverTargetInfo, systemPolicy *resolver.SystemResolverPolicy, streamClient *resolver.StreamClient, doqClient *resolver.DoQClient, dohClient *resolver.DOHClient) []queryResult {
	results := make([]queryResult, len(inspectTypes))
	var wg sync.WaitGroup
	for i, qt := range inspectTypes {
		wg.Add(1)
		go func(i int, qt queryType) {
			defer wg.Done()
			results[i].typ = qt
			switch {
			case systemPolicy != nil:
				results[i].records, results[i].tcpFallback, results[i].err = lookupSystemRecords(ctx, systemPolicy, host, qt)
			case streamClient != nil:
				results[i].records, results[i].err = lookupStreamRecords(ctx, streamClient, host, qt)
			case doqClient != nil:
				results[i].records, results[i].err = lookupDoQRecords(ctx, doqClient, host, qt)
			case dohClient != nil:
				results[i].records, results[i].err = lookupDOHRecordsWithClient(ctx, dohClient, host, qt)
			default:
				results[i].records, results[i].tcpFallback, results[i].err = lookupUDPRecordsWithFallback(ctx, target.udpAddr, host, qt)
			}
		}(i, qt)
	}
	wg.Wait()
	return results
}

// lookupSystemRecords resolves host for one record type through the system
// nameservers, retrying across them per the resolv.conf policy.
func lookupSystemRecords(ctx context.Context, policy *resolver.SystemResolverPolicy, host string, qt queryType) ([]record, bool, error) {
	// resolvectl does not expose TTLs. DNS inspection must query the configured
	// nameserver directly so every displayed record has authoritative TTL data.
	inspectionPolicy := *policy
	inspectionPolicy.UseSystemdResolved = false
	resolved, fallback, err := resolver.QuerySystemType(ctx, inspectionPolicy, host, uint16(qt.dnsType))
	if err != nil {
		return nil, fallback, err
	}
	records := make([]record, 0, len(resolved))
	for _, rec := range resolved {
		value, ok := wireRecordValue(rec)
		if !ok {
			continue
		}
		records = append(records, record{typ: typeLabel(dnsmessage.Type(rec.Type)), value: value, ttl: rec.TTL, hasTTL: rec.TTLPresent})
	}
	return records, fallback, nil
}

// aggregate merges per-type query results into out. It returns the first
// non-NODATA error so callers that produce nothing can explain the failure.
func aggregate(out *result, results []queryResult, start time.Time) error {
	var firstResult error
	seen := make(map[string]int)
	out.queryTotal = len(results)
	out.queries = make([]queryResult, 0, len(results))
	for _, query := range results {
		query.status = classifyQuery(query)
		out.queries = append(out.queries, query)
		out.tcpFallback = out.tcpFallback || query.tcpFallback
		switch query.status {
		case queryStatusFailed:
			out.failures = append(out.failures, queryFailure{label: query.typ.label, err: query.err})
			if firstResult == nil {
				firstResult = query.err
			}
		case queryStatusNoData:
			out.queryNoData++
		case queryStatusData:
			out.queryWithData++
		}
		for _, rec := range query.records {
			key := rec.typ + "\x00" + rec.value
			if idx, ok := seen[key]; ok {
				records := out.records[rec.typ]
				existing := &records[idx]
				switch {
				case rec.hasTTL && !existing.hasTTL:
					existing.ttl = rec.ttl
					existing.hasTTL = true
				case rec.hasTTL && existing.hasTTL && rec.ttl < existing.ttl:
					existing.ttl = rec.ttl
				}
				continue
			}
			seen[key] = len(out.records[rec.typ])
			out.records[rec.typ] = append(out.records[rec.typ], rec)
		}
	}
	out.duration = time.Since(start)
	return firstResult
}

func classifyQuery(query queryResult) queryStatus {
	if query.err != nil {
		if errors.Is(query.err, resolver.ErrDNSNoData) {
			return queryStatusNoData
		}
		return queryStatusFailed
	}
	if len(query.records) == 0 {
		return queryStatusNoData
	}
	return queryStatusData
}

func hasAddressRecords(out *result) bool {
	return len(out.records["A"]) > 0 || len(out.records["AAAA"]) > 0
}

// platformLookup resolves host through the platform resolver and fills out,
// reporting per-record TTLs as unavailable.
func platformLookup(ctx context.Context, out *result, host string, start time.Time) (*result, error) {
	records, err := lookupDefaultResolverRecords(ctx, host)
	out.duration = time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", host, err)
	}
	for _, rec := range records {
		out.records[rec.typ] = append(out.records[rec.typ], rec)
	}
	if recordCount(out) == 0 {
		return nil, fmt.Errorf("lookup %s: no DNS records found", host)
	}
	return out, nil
}

// contextForDirectLookup reserves one quarter of a timed inspection for
// the platform fallback. Direct queries remain concurrent, so this only
// affects slow or unreachable system nameservers.
func contextForDirectLookup(ctx context.Context, reserve bool) (context.Context, context.CancelFunc) {
	if !reserve {
		return ctx, func() {}
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, time.Now().Add(remaining*3/4))
}

func dnsQueryHost(host string) (string, error) {
	trailingDot := strings.HasSuffix(host, ".")
	base := strings.TrimSuffix(host, ".")
	if base == "" {
		if trailingDot {
			return ".", nil
		}
		return "", errors.New("hostname is empty")
	}
	labels := strings.Split(base, ".")
	for i, label := range labels {
		if label == "" {
			return "", errors.New("hostname contains an empty label")
		}
		if isASCII(label) {
			// DNS service labels such as _acme-challenge are valid ASCII
			// labels but are not valid IDNA labels.
			continue
		}
		ascii, err := idna.Lookup.ToASCII(label)
		if err != nil {
			return "", err
		}
		labels[i] = ascii
	}
	ascii := strings.Join(labels, ".")
	if trailingDot {
		return ascii + ".", nil
	}
	return ascii, nil
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// platformResult combines platform A/AAAA records with records already
// returned by the system nameserver. This keeps useful non-address records
// visible while making the mixed resolver provenance and unavailable TTLs
// explicit.
func platformResult(orig *result, records []record, start time.Time) *result {
	out := &result{
		host:           orig.host,
		queryName:      orig.queryName,
		resolver:       orig.resolver + " (platform fallback)",
		transport:      "mixed",
		security:       "mixed (direct nameserver and platform resolver)",
		source:         "system resolver configuration with platform fallback",
		records:        make(map[string][]record, len(orig.records)),
		queries:        slices.Clone(orig.queries),
		failures:       slices.Clone(orig.failures),
		queryTotal:     orig.queryTotal,
		queryWithData:  orig.queryWithData,
		queryNoData:    orig.queryNoData,
		tcpFallback:    orig.tcpFallback,
		silent:         orig.silent,
		duration:       time.Since(start),
		ttlUnavailable: true,
	}
	for typ, values := range orig.records {
		out.records[typ] = slices.Clone(values)
	}
	for _, rec := range records {
		out.records[rec.typ] = append(out.records[rec.typ], rec)
	}
	return out
}

func lookupDefaultResolverRecords(ctx context.Context, host string) ([]record, error) {
	addrs, err := defaultLookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	records := make([]record, 0, len(addrs))
	for _, addr := range addrs {
		ip := addr.IP
		switch {
		case ip.To4() != nil:
			records = append(records, record{typ: "A", value: ip.String()})
		case ip.To16() != nil:
			records = append(records, record{typ: "AAAA", value: ip.String()})
		}
	}
	return records, nil
}

func lookupStreamRecords(ctx context.Context, client *resolver.StreamClient, host string, qt queryType) ([]record, error) {
	name, err := resolver.ParseName(absoluteName(host))
	if err != nil {
		return nil, err
	}
	question := resolver.Question{Name: name, Type: uint16(qt.dnsType), Class: 1}
	message, err := client.Query(ctx, absoluteName(host), uint16(qt.dnsType))
	if err != nil {
		return nil, err
	}
	if message.Header.RCode != 0 {
		return nil, fmt.Errorf("no DNS records found: %s", resolver.RCodeName(message.Header.RCode))
	}
	authorized, err := resolver.AuthorizeAnswers(message, question)
	if err != nil {
		return nil, err
	}
	records := make([]record, 0, len(authorized))
	for _, answer := range authorized {
		value, ok := wireRecordValue(answer)
		if ok {
			records = append(records, record{typ: typeLabel(dnsmessage.Type(answer.Type)), value: value, ttl: answer.TTL, hasTTL: true})
		}
	}
	return records, nil
}

func lookupDoQRecords(ctx context.Context, client *resolver.DoQClient, host string, qt queryType) ([]record, error) {
	name, err := resolver.ParseName(absoluteName(host))
	if err != nil {
		return nil, err
	}
	question := resolver.Question{Name: name, Type: uint16(qt.dnsType), Class: 1}
	message, err := client.Query(ctx, absoluteName(host), uint16(qt.dnsType))
	if err != nil {
		return nil, err
	}
	if message.Header.RCode != 0 {
		return nil, fmt.Errorf("no DNS records found: %s", resolver.RCodeName(message.Header.RCode))
	}
	authorized, err := resolver.AuthorizeAnswers(message, question)
	if err != nil {
		return nil, err
	}
	records := make([]record, 0, len(authorized))
	for _, answer := range authorized {
		value, ok := wireRecordValue(answer)
		if ok {
			records = append(records, record{typ: typeLabel(dnsmessage.Type(answer.Type)), value: value, ttl: answer.TTL, hasTTL: true})
		}
	}
	return records, nil
}

func lookupDOHRecordsWithClient(ctx context.Context, client *resolver.DOHClient, host string, qt queryType) ([]record, error) {
	answers, err := client.LookupInspectionType(ctx, host, qt.dohType, int(qt.dnsType))
	if err != nil {
		return nil, err
	}
	out := make([]record, 0, len(answers))
	for _, answer := range answers {
		typ := dnsmessage.Type(answer.Record.Type)
		value := ""
		if answer.Data != "" {
			value = normalizeDOHValue(typ, answer.Data)
		} else {
			value, _ = wireRecordValue(answer.Record)
		}
		if value == "" {
			continue
		}
		out = append(out, record{typ: typeLabel(typ), value: value, ttl: answer.Record.TTL, hasTTL: answer.TTLPresent})
	}
	return out, nil
}

func lookupUDPRecords(ctx context.Context, serverAddr, host string, qt queryType) ([]record, error) {
	records, _, err := lookupUDPRecordsWithFallback(ctx, serverAddr, host, qt)
	return records, err
}

func lookupUDPRecordsWithFallback(ctx context.Context, serverAddr, host string, qt queryType) ([]record, bool, error) {
	name, err := resolver.ParseName(absoluteName(host))
	if err != nil {
		return nil, false, err
	}
	question := resolver.Question{Name: name, Type: uint16(qt.dnsType), Class: 1}
	res, fallback, err := resolver.LookupUDPMessage(ctx, serverAddr, absoluteName(host), uint16(qt.dnsType))
	if err != nil {
		return nil, fallback, err
	}
	if res.Header.RCode != 0 {
		return nil, fallback, fmt.Errorf("no DNS records found: %s", resolver.RCodeName(res.Header.RCode))
	}

	authorized, err := resolver.AuthorizeAnswers(res, question)
	if err != nil {
		return nil, fallback, err
	}
	records := make([]record, 0, len(authorized))
	for _, answer := range authorized {
		value, ok := wireRecordValue(answer)
		if !ok {
			continue
		}
		records = append(records, record{typ: typeLabel(dnsmessage.Type(answer.Type)), value: value, ttl: answer.TTL, hasTTL: true})
	}
	return records, fallback, nil
}

func wireRecordValue(res resolver.Record) (string, bool) {
	switch res.Type {
	case uint16(dnsmessage.TypeA), uint16(dnsmessage.TypeAAAA):
		if ip := resolver.RecordAddress(res); ip != nil {
			return ip.String(), true
		}
	case uint16(dnsmessage.TypeCNAME), uint16(dnsmessage.TypeNS):
		if res.Target != nil {
			return res.Target.String(), true
		}
	case uint16(dnsmessage.TypeTXT):
		parts := make([]string, 0, len(res.TXT))
		for _, part := range res.TXT {
			parts = append(parts, string(part))
		}
		return strings.Join(parts, " "), true
	case uint16(dnsmessage.TypeMX):
		if res.Target != nil {
			return fmt.Sprintf("%d %s", res.Preference, res.Target), true
		}
	case uint16(dnsmessage.TypeSOA):
		if res.Target != nil && res.Target2 != nil {
			return fmt.Sprintf("%s %s serial=%d refresh=%d retry=%d expire=%d minttl=%d",
				res.Target, res.Target2, res.SOAValues[0], res.SOAValues[1], res.SOAValues[2], res.SOAValues[3], res.SOAValues[4]), true
		}
	case uint16(dnsmessage.TypeSRV):
		if res.Target != nil {
			return fmt.Sprintf("%d %d %d %s", res.Priority, res.Weight, res.Port, res.Target), true
		}
	case uint16(dnsTypeCAA):
		return formatCAA(res.RData), true
	case uint16(dnsmessage.TypeSVCB), uint16(dnsmessage.TypeHTTPS):
		params := make([]dnsmessage.SVCParam, 0, len(res.Params))
		for _, param := range res.Params {
			params = append(params, dnsmessage.SVCParam{Key: dnsmessage.SVCParamKey(param.Key), Value: append([]byte(nil), param.Value...)})
		}
		if res.Target != nil {
			return formatSVCBValue(res.Priority, res.Target.String(), params), true
		}
	}
	return "0x" + hex.EncodeToString(res.RData), true
}

func formatCAA(raw []byte) string {
	if len(raw) < 2 {
		return "0x" + hex.EncodeToString(raw)
	}
	tagLen := int(raw[1])
	if len(raw) < 2+tagLen {
		return "0x" + hex.EncodeToString(raw)
	}
	flags := raw[0]
	tag := string(raw[2 : 2+tagLen])
	value := string(raw[2+tagLen:])
	return fmt.Sprintf("%d %s %q", flags, tag, value)
}

func formatSVCBValue(priority uint16, target string, params []dnsmessage.SVCParam) string {
	parts := []string{fmt.Sprintf("%d", priority), target}
	for _, param := range params {
		parts = append(parts, formatSVCParam(param))
	}
	return strings.Join(parts, " ")
}

func formatSVCParam(param dnsmessage.SVCParam) string {
	switch param.Key {
	case dnsmessage.SVCParamALPN:
		var alpns []string
		for i := 0; i < len(param.Value); {
			ln := int(param.Value[i])
			i++
			if i+ln > len(param.Value) {
				return fmt.Sprintf("%s=0x%s", param.Key.String(), hex.EncodeToString(param.Value))
			}
			alpns = append(alpns, string(param.Value[i:i+ln]))
			i += ln
		}
		return param.Key.String() + "=" + strings.Join(alpns, ",")
	case dnsmessage.SVCParamNoDefaultALPN:
		return param.Key.String()
	case dnsmessage.SVCParamECH:
		return "ECH=" + base64.StdEncoding.EncodeToString(param.Value)
	case dnsmessage.SVCParamPort:
		if len(param.Value) != 2 {
			return fmt.Sprintf("%s=0x%s", param.Key.String(), hex.EncodeToString(param.Value))
		}
		port := uint16(param.Value[0])<<8 | uint16(param.Value[1])
		return fmt.Sprintf("%s=%d", param.Key.String(), port)
	case dnsmessage.SVCParamIPv4Hint:
		if len(param.Value)%4 != 0 {
			return fmt.Sprintf("%s=0x%s", param.Key.String(), hex.EncodeToString(param.Value))
		}
		var ips []string
		for i := 0; i < len(param.Value); i += 4 {
			ips = append(ips, net.IP(param.Value[i:i+4]).String())
		}
		return param.Key.String() + "=" + strings.Join(ips, ",")
	case dnsmessage.SVCParamIPv6Hint:
		if len(param.Value)%16 != 0 {
			return fmt.Sprintf("%s=0x%s", param.Key.String(), hex.EncodeToString(param.Value))
		}
		var ips []string
		for i := 0; i < len(param.Value); i += 16 {
			ips = append(ips, net.IP(param.Value[i:i+16]).String())
		}
		return param.Key.String() + "=" + strings.Join(ips, ",")
	case dnsmessage.SVCParamDOHPath:
		return param.Key.String() + "=" + strconv.Quote(string(param.Value))
	default:
		return fmt.Sprintf("%s=0x%s", param.Key.String(), hex.EncodeToString(param.Value))
	}
}

func normalizeDOHValue(typ dnsmessage.Type, value string) string {
	raw, ok := parseGenericRDATA(value)
	if !ok {
		return value
	}

	switch typ {
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		if text, ok := parseSVCBRDATA(raw); ok {
			return text
		}
	case dnsTypeCAA:
		return formatCAA(raw)
	}
	return "0x" + hex.EncodeToString(raw)
}

func parseGenericRDATA(value string) ([]byte, bool) {
	fields := strings.Fields(value)
	if len(fields) < 3 || fields[0] != "\\#" {
		return nil, false
	}
	wantLen, err := strconv.Atoi(fields[1])
	if err != nil || wantLen < 0 {
		return nil, false
	}
	raw, err := hex.DecodeString(strings.Join(fields[2:], ""))
	if err != nil || len(raw) != wantLen {
		return nil, false
	}
	return raw, true
}

func parseSVCBRDATA(raw []byte) (string, bool) {
	if len(raw) < 3 {
		return "", false
	}
	priority := uint16(raw[0])<<8 | uint16(raw[1])
	target, off, ok := unpackDNSName(raw, 2)
	if !ok {
		return "", false
	}

	var params []dnsmessage.SVCParam
	for off < len(raw) {
		if off+4 > len(raw) {
			return "", false
		}
		key := uint16(raw[off])<<8 | uint16(raw[off+1])
		ln := int(raw[off+2])<<8 | int(raw[off+3])
		off += 4
		if off+ln > len(raw) {
			return "", false
		}
		value := append([]byte(nil), raw[off:off+ln]...)
		params = append(params, dnsmessage.SVCParam{Key: dnsmessage.SVCParamKey(key), Value: value})
		off += ln
	}
	return formatSVCBValue(priority, target, params), true
}

func unpackDNSName(raw []byte, off int) (string, int, bool) {
	var labels []string
	for {
		if off >= len(raw) {
			return "", 0, false
		}
		ln := int(raw[off])
		off++
		if ln == 0 {
			if len(labels) == 0 {
				return ".", off, true
			}
			return strings.Join(labels, ".") + ".", off, true
		}
		if ln&0xc0 != 0 || off+ln > len(raw) {
			return "", 0, false
		}
		labels = append(labels, string(raw[off:off+ln]))
		off += ln
	}
}

func resolverSecurity(cfg *Config, server *url.URL) string {
	if server == nil {
		return "platform resolver (OS-managed security)"
	}
	if cfg.Endpoint != nil {
		security := cfg.Endpoint.Security
		if cfg.Insecure && security == resolver.SecurityVerifiedEncrypted {
			security = resolver.SecurityUnverifiedEncrypt
		}
		return string(security)
	}
	if cfg.Insecure && (strings.EqualFold(server.Scheme, "https") || strings.EqualFold(server.Scheme, "http")) {
		return string(resolver.SecurityUnverifiedEncrypt)
	}
	if strings.EqualFold(server.Scheme, "https") {
		return string(resolver.SecurityVerifiedEncrypted)
	}
	return string(resolver.SecurityPlaintext)
}

func resolverTarget(server *url.URL) resolverTargetInfo {
	switch {
	case server == nil:
		return resolverTargetInfo{label: "system resolver", useDefault: true}
	case server.Scheme == "":
		return resolverTargetInfo{label: server.Host, udpAddr: server.Host}
	default:
		return resolverTargetInfo{label: server.String()}
	}
}

func inspectionSource(server *url.URL) string {
	if server == nil {
		return "system resolver configuration"
	}
	return "configured resolver endpoint"
}

func inspectionTransport(cfg *Config, server *url.URL) string {
	if cfg.Endpoint != nil {
		return displayTransport(cfg.Endpoint.Transport)
	}
	if server == nil {
		return "platform resolver"
	}
	switch strings.ToLower(server.Scheme) {
	case "tcp":
		return "TCP"
	case "tls", "dot":
		return "TLS (DoT)"
	case "quic", "doq":
		return "QUIC (DoQ)"
	case "http", "https":
		return "HTTPS (DoH)"
	default:
		return "UDP"
	}
}

func displayTransport(transport resolver.Transport) string {
	switch transport {
	case resolver.TransportTCP:
		return "TCP"
	case resolver.TransportTLS:
		return "TLS (DoT)"
	case resolver.TransportQUIC:
		return "QUIC (DoQ)"
	case resolver.TransportHTTPS:
		return "HTTPS (DoH)"
	default:
		return "UDP"
	}
}

func displaySecurity(security string) string {
	switch security {
	case string(resolver.SecurityPlaintext):
		return "plaintext"
	case string(resolver.SecurityVerifiedEncrypted):
		return "verified TLS"
	case string(resolver.SecurityUnverifiedEncrypt):
		return "encrypted, certificate verification disabled"
	case "platform resolver (OS-managed security)":
		return "OS-managed / unknown to fetch"
	default:
		return security
	}
}

func absoluteName(host string) string {
	if strings.HasSuffix(host, ".") {
		return host
	}
	return host + "."
}

func typeLabel(typ dnsmessage.Type) string {
	switch typ {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeSOA:
		return "SOA"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsTypeCAA:
		return "CAA"
	case dnsmessage.TypeSVCB:
		return "SVCB"
	case dnsmessage.TypeHTTPS:
		return "HTTPS"
	default:
		return fmt.Sprintf("TYPE%d", uint16(typ))
	}
}

func renderIPLiteral(p *core.Printer, host string) {
	renderInspectionSection(p, "Lookup")
	writeInspectionField(p, "Name", host)
	writeInspectionField(p, "Status", "IP literal — DNS not performed")
}

const maxPartialErrorBytes = 256

func conciseDiagnostic(text string) string {
	if len(text) <= maxPartialErrorBytes {
		return text
	}
	cut := maxPartialErrorBytes
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "..."
}

func render(p *core.Printer, res *result) {
	renderWithWarning(p, p, res)
}

func renderWithWarning(p, warningOutput *core.Printer, res *result) {
	renderInspection(p, res)
	if res.tcpFallback {
		core.WriteWarningMsgIf(warningOutput, "UDP response was truncated; used TCP fallback", res.silent)
	}
}

// renderInspection writes the structured DNS diagnostic view. The lookup
// summary is deliberately separate from record rendering so that the output
// remains useful even when no record data is available.
func renderInspection(p *core.Printer, res *result) {
	renderInspectionSection(p, "Lookup")
	writeInspectionField(p, "Name", res.host)
	if res.queryName != "" && res.queryName != res.host {
		writeInspectionField(p, "Query name", res.queryName)
	}
	if res.resolver != "" {
		writeInspectionField(p, "Resolver", res.resolver)
	}
	if res.transport != "" {
		writeInspectionField(p, "Transport", res.transport)
	}
	if res.security != "" {
		writeInspectionField(p, "Transport security", displaySecurity(res.security))
	}
	if res.source != "" {
		writeInspectionField(p, "Source", res.source)
	}
	writeInspectionField(p, "Status", inspectionStatus(res))
	if summary := resultSummary(res); summary != "" {
		writeInspectionField(p, "Results", summary)
	}
	if summary := querySummary(res); summary != "" {
		writeInspectionField(p, "Queries", summary)
	}
	if res.duration > 0 {
		writeInspectionField(p, "Timing", formatDuration(res.duration))
	}

	if len(res.failures) > 0 {
		writeInspectionBlankLine(p)
		renderInspectionSection(p, "Failures")
		renderFailures(p, res.failures)
	}
	writeInspectionBlankLine(p)
	renderInspectionSection(p, "Records")
	if recordCount(res) == 0 {
		return
	}
	for _, qt := range inspectTypes {
		renderSection(p, qt.label, res.records[qt.label])
	}
	renderOtherSections(p, res.records)
}

func renderFailures(p *core.Printer, failures []queryFailure) {
	type failureGroup struct {
		labels []string
		err    string
	}
	groups := make([]failureGroup, 0, len(failures))
	indices := make(map[string]int, len(failures))
	for _, failure := range failures {
		errText := "query failed"
		if failure.err != nil {
			errText = conciseDiagnostic(failure.err.Error())
		}
		idx, ok := indices[errText]
		if !ok {
			indices[errText] = len(groups)
			groups = append(groups, failureGroup{err: errText})
			idx = len(groups) - 1
		}
		groups[idx].labels = append(groups[idx].labels, failure.label)
	}
	for _, group := range groups {
		label := strings.Join(group.labels, ", ")
		if len(group.labels) == len(inspectTypes) {
			label = "All record types"
		}
		writeInspectionField(p, label, group.err)
	}
}

func renderInspectionSection(p *core.Printer, heading string) {
	p.WriteInfoPrefix()
	p.Set(core.Bold)
	p.WriteString(core.TerminalSafeText(heading))
	p.Reset()
	p.WriteString("\n")
}

func writeInspectionField(p *core.Printer, label, value string) {
	p.WriteInfoPrefix()
	p.WriteString("  ")
	p.WriteString(label)
	p.WriteString(": ")
	p.WriteString(core.TerminalSafeText(value))
	p.WriteString("\n")
}

func writeInspectionBlankLine(p *core.Printer) {
	p.WriteInfoPrefix()
	p.WriteString("\n")
}

func inspectionStatus(res *result) string {
	if len(res.failures) == 0 {
		return "complete"
	}
	if res.queryTotal > 0 {
		return fmt.Sprintf("incomplete — %d of %d queries failed", len(res.failures), res.queryTotal)
	}
	return "incomplete"
}

func resultSummary(res *result) string {
	addresses := len(res.records["A"]) + len(res.records["AAAA"])
	return strings.Join([]string{
		countPhrase(addresses, "address", "addresses"),
		countPhrase(recordCount(res), "record", "records"),
		countPhrase(recordTypeCount(res), "record type", "record types"),
	}, " · ")
}

func querySummary(res *result) string {
	if res.queryTotal == 0 {
		return ""
	}
	parts := []string{
		queryCountPhrase(res.queryTotal, "total"),
		queryCountPhrase(res.queryWithData, "with data"),
		queryCountPhrase(res.queryNoData, "no data"),
	}
	if len(res.failures) > 0 {
		parts = append(parts, queryCountPhrase(len(res.failures), "failed"))
	}
	return strings.Join(parts, " · ")
}

func countPhrase(count int, singular, plural string) string {
	if count == 1 {
		return fmt.Sprintf("1 %s", singular)
	}
	return fmt.Sprintf("%d %s", count, plural)
}

func queryCountPhrase(count int, label string) string {
	return fmt.Sprintf("%d %s", count, label)
}

func recordTypeCount(res *result) int {
	count := 0
	for _, records := range res.records {
		if len(records) > 0 {
			count++
		}
	}
	return count
}

func renderOtherSections(p *core.Printer, records map[string][]record) {
	known := make(map[string]bool, len(inspectTypes))
	for _, qt := range inspectTypes {
		known[qt.label] = true
	}
	var types []string
	for typ := range records {
		if known[typ] {
			continue
		}
		types = append(types, typ)
	}
	slices.Sort(types)
	for _, typ := range types {
		renderSection(p, typ, records[typ])
	}
}

func renderSection(p *core.Printer, name string, records []record) {
	if len(records) == 0 {
		return
	}
	records = slices.Clone(records)
	slices.SortFunc(records, func(a, b record) int {
		if cmp := strings.Compare(a.value, b.value); cmp != 0 {
			return cmp
		}
		if a.ttl < b.ttl {
			return -1
		}
		if a.ttl > b.ttl {
			return 1
		}
		return 0
	})

	p.WriteInfoPrefix()
	p.Set(core.Bold)
	p.WriteString("  " + name)
	p.Reset()
	p.WriteString("\n")

	for i, rec := range records {
		p.WriteInfoPrefix()
		if i == len(records)-1 {
			p.WriteString("  \u2514\u2500 ")
		} else {
			p.WriteString("  \u251c\u2500 ")
		}
		p.Set(core.Green)
		p.WriteString(core.TerminalSafeText(rec.value))
		p.Reset()
		p.WriteString(" ")
		p.Set(core.Dim)
		if rec.hasTTL {
			p.WriteString("(TTL ")
			p.WriteString(formatTTL(rec.ttl))
			p.WriteString(")")
		} else {
			p.WriteString("(TTL unavailable)")
		}
		p.Reset()
		p.WriteString("\n")
	}

	p.WriteInfoPrefix()
	p.WriteString("\n")
}

func recordCount(res *result) int {
	var count int
	for _, records := range res.records {
		count += len(records)
	}
	return count
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(100 * time.Microsecond).String()
}

func formatTTL(ttl uint32) string {
	if ttl == 1 {
		return "1s"
	}
	d := time.Duration(ttl) * time.Second
	if ttl < 60 {
		return d.String()
	}
	text := strings.TrimSuffix(d.String(), "0s")
	return strings.TrimSuffix(text, "0m")
}

func flushInspectionOutput(output, errorOutput *core.Printer) int {
	if err := output.Flush(); err != nil {
		if core.IsBrokenPipe(err) {
			return 0
		}
		writeDNSError(errorOutput, err)
		return 1
	}
	return 0
}

func writeDNSError(p *core.Printer, err error) {
	core.WriteErrorMsgNoFlush(p, err)
	p.Flush()
}
