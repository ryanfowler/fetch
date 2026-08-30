package dnsinspect

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
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
	Verbosity  core.Verbosity

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

type recordSource uint8

const (
	recordSourceDNS recordSource = iota
	recordSourcePlatform
)

// record keeps DNS data in semantic form until it reaches the renderer.
// presentation is only a fallback for DoH JSON and unknown record types whose
// provider did not supply wire-format RDATA.
type record struct {
	owner        string
	typ          dnsmessage.Type
	ttl          uint32
	hasTTL       bool
	source       recordSource
	address      net.IP
	target       string
	target2      string
	preference   uint16
	priority     uint16
	weight       uint16
	port         uint16
	soa          [5]uint32
	txt          [][]byte
	params       []resolver.SVCParam
	rawRData     []byte
	presentation string
}

type result struct {
	host             string
	queryName        string
	resolver         string
	responders       []string
	transport        string
	security         string
	source           string
	records          map[string][]record
	queries          []queryResult
	failures         []queryFailure
	queryTotal       int
	queryWithData    int
	queryNoData      int
	duration         time.Duration
	tcpFallback      bool
	platformFallback bool
	verbosity        core.Verbosity
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
	responder   string
	transport   resolver.Transport
	attempts    int
	duration    time.Duration
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
	render(output, res)
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
		security:  resolverTransportSecurity(cfg, server),
		source:    inspectionSource(server),
		records:   make(map[string][]record),
		verbosity: cfg.Verbosity,
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
			out.resolver = "platform resolver"
			out.transport = "platform resolver"
			out.security = "platform resolver (OS-managed security)"
			out.source = "platform resolver"
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
	if systemPolicy != nil {
		setSystemResponderSummary(out)
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
			queryStart := time.Now()
			results[i].typ = qt
			switch {
			case systemPolicy != nil:
				var metadata resolver.QueryMetadata
				results[i].records, metadata, results[i].err = lookupSystemRecords(ctx, systemPolicy, host, qt)
				results[i].responder = metadata.Server
				results[i].transport = metadata.Transport
				results[i].attempts = metadata.Attempts
				results[i].duration = metadata.Duration
				results[i].tcpFallback = metadata.TCPFallback
			case streamClient != nil:
				results[i].records, results[i].err = lookupStreamRecords(ctx, streamClient, host, qt)
			case doqClient != nil:
				results[i].records, results[i].err = lookupDoQRecords(ctx, doqClient, host, qt)
			case dohClient != nil:
				results[i].records, results[i].err = lookupDOHRecordsWithClient(ctx, dohClient, host, qt)
			default:
				results[i].records, results[i].tcpFallback, results[i].err = lookupUDPRecordsWithFallback(ctx, target.udpAddr, host, qt)
			}
			// System-nameserver queries expose resolver metadata that includes
			// failover and retry time. The other backends do not, so measure
			// their query operation here. This starts after shared resolver
			// setup, which prevents bootstrap/connect time from being charged
			// to every concurrently issued query.
			if results[i].duration <= 0 {
				results[i].duration = time.Since(queryStart)
			}
		}(i, qt)
	}
	wg.Wait()
	return results
}

// lookupSystemRecords resolves host for one record type through the system
// nameservers, retrying across them per the resolv.conf policy. The metadata
// identifies the nameserver that produced the response, not merely the first
// configured nameserver.
func lookupSystemRecords(ctx context.Context, policy *resolver.SystemResolverPolicy, host string, qt queryType) ([]record, resolver.QueryMetadata, error) {
	// resolvectl does not expose TTLs. DNS inspection must query the configured
	// nameserver directly so every displayed record has authoritative TTL data.
	inspectionPolicy := *policy
	inspectionPolicy.UseSystemdResolved = false
	resolved, metadata, err := resolver.QuerySystemTypeDetailed(ctx, inspectionPolicy, host, uint16(qt.dnsType))
	if err != nil {
		return nil, metadata, err
	}
	records := make([]record, 0, len(resolved))
	for _, rec := range resolved {
		if converted, ok := recordFromWire(rec); ok {
			records = append(records, converted)
		}
	}
	return records, metadata, nil
}

// setSystemResponderSummary replaces the configured-nameserver placeholder
// with the exact responders observed during this inspection. A failed query
// has no responder, so it cannot make the summary claim that a server replied.
func setSystemResponderSummary(out *result) {
	responders := make([]string, 0, len(out.queries))
	seen := make(map[string]struct{}, len(out.queries))
	for _, query := range out.queries {
		if query.responder == "" {
			continue
		}
		if _, ok := seen[query.responder]; ok {
			continue
		}
		seen[query.responder] = struct{}{}
		responders = append(responders, query.responder)
	}
	slices.Sort(responders)
	out.responders = responders
	switch len(responders) {
	case 0:
		out.resolver = "system resolver (configured nameservers)"
	case 1:
		out.resolver = responders[0]
	default:
		out.resolver = ""
		out.responders = responders
	}
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
			label := typeLabel(rec.typ)
			key := canonicalOwnerKey(rec.owner) + "\x00" + strconv.Itoa(int(rec.typ)) + "\x00" + rec.semanticKey()
			if idx, ok := seen[key]; ok {
				records := out.records[label]
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
			seen[key] = len(out.records[label])
			out.records[label] = append(out.records[label], rec)
		}
	}
	out.duration = time.Since(start)
	return firstResult
}

func canonicalOwnerKey(owner string) string {
	return strings.ToLower(owner)
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
		label := typeLabel(rec.typ)
		out.records[label] = append(out.records[label], rec)
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
		host:             orig.host,
		queryName:        orig.queryName,
		resolver:         "system nameservers + platform resolver",
		transport:        "mixed",
		security:         "mixed",
		source:           "system resolver configuration + platform resolver",
		responders:       append(slices.Clone(orig.responders), "platform resolver"),
		records:          make(map[string][]record, len(orig.records)),
		queries:          slices.Clone(orig.queries),
		failures:         slices.Clone(orig.failures),
		queryTotal:       orig.queryTotal,
		queryWithData:    orig.queryWithData,
		queryNoData:      orig.queryNoData,
		tcpFallback:      orig.tcpFallback,
		platformFallback: true,
		verbosity:        orig.verbosity,
		duration:         time.Since(start),
	}
	for typ, values := range orig.records {
		out.records[typ] = slices.Clone(values)
	}
	for _, rec := range records {
		label := typeLabel(rec.typ)
		out.records[label] = append(out.records[label], rec)
	}
	return out
}

func lookupDefaultResolverRecords(ctx context.Context, host string) ([]record, error) {
	addrs, err := defaultLookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	records := make([]record, 0, len(addrs))
	owner := normalizedOwner(host)
	for _, addr := range addrs {
		ip := addr.IP
		switch {
		case ip.To4() != nil:
			records = append(records, record{owner: owner, typ: dnsmessage.TypeA, address: append(net.IP(nil), ip.To4()...), source: recordSourcePlatform})
		case ip.To16() != nil:
			records = append(records, record{owner: owner, typ: dnsmessage.TypeAAAA, address: append(net.IP(nil), ip.To16()...), source: recordSourcePlatform})
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
		if converted, ok := recordFromWire(answer); ok {
			records = append(records, converted)
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
		if converted, ok := recordFromWire(answer); ok {
			records = append(records, converted)
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
		if rec, ok := recordFromDOH(answer); ok {
			out = append(out, rec)
		}
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
		if converted, ok := recordFromWire(answer); ok {
			records = append(records, converted)
		}
	}
	return records, fallback, nil
}

func recordFromWire(res resolver.Record) (record, bool) {
	return semanticRecord(res, "", res.TTLPresent), true
}

func recordFromDOH(answer resolver.DOHRecord) (record, bool) {
	rec := semanticRecord(answer.Record, answer.Data, answer.TTLPresent)
	return rec, rec.hasSemanticData()
}

func (rec record) hasSemanticData() bool {
	switch rec.typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		return len(rec.address) > 0
	case dnsmessage.TypeCNAME, dnsmessage.TypeNS:
		return rec.target != ""
	case dnsmessage.TypeTXT:
		return rec.txt != nil
	case dnsmessage.TypeMX, dnsmessage.TypeSRV:
		return rec.target != ""
	case dnsmessage.TypeSOA:
		return rec.target != "" && rec.target2 != ""
	case dnsTypeCAA:
		return len(rec.rawRData) >= 2
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		return rec.target != ""
	default:
		return rec.presentation != "" || rec.rawRData != nil
	}
}

func semanticRecord(res resolver.Record, presentation string, ttlPresent bool) record {
	rec := record{
		owner:        normalizeOwnerPresentation(res.Owner.String()),
		typ:          dnsmessage.Type(res.Type),
		ttl:          res.TTL,
		hasTTL:       ttlPresent,
		source:       recordSourceDNS,
		preference:   res.Preference,
		priority:     res.Priority,
		weight:       res.Weight,
		port:         res.Port,
		soa:          res.SOAValues,
		rawRData:     append([]byte(nil), res.RData...),
		presentation: presentation,
	}
	if ip := resolver.RecordAddress(res); ip != nil {
		rec.address = append(net.IP(nil), ip...)
	}
	if res.Target != nil {
		rec.target = res.Target.String()
	}
	if res.Target2 != nil {
		rec.target2 = res.Target2.String()
	}
	for _, chunk := range res.TXT {
		rec.txt = append(rec.txt, append([]byte(nil), chunk...))
	}
	for _, param := range res.Params {
		rec.params = append(rec.params, resolver.SVCParam{Key: param.Key, Value: append([]byte(nil), param.Value...)})
	}
	populateRecordData(&rec)
	return rec
}

func populateRecordData(rec *record) {
	if len(rec.rawRData) > 0 {
		populateRecordFromRaw(rec)
	}
	if rec.presentation == "" {
		return
	}
	if _, generic := parseGenericRDATA(rec.presentation); generic {
		return
	}
	populateRecordFromPresentation(rec)
}

func populateRecordFromRaw(rec *record) {
	raw := rec.rawRData
	switch rec.typ {
	case dnsmessage.TypeNS:
		if target, end, ok := unpackDNSName(raw, 0); ok && end == len(raw) {
			rec.target = target
		}
	case dnsmessage.TypeMX:
		if len(raw) >= 3 {
			if target, end, ok := unpackDNSName(raw, 2); ok && end == len(raw) {
				rec.preference = binary.BigEndian.Uint16(raw)
				rec.target = target
			}
		}
	case dnsmessage.TypeSOA:
		if first, off, ok := unpackDNSName(raw, 0); ok {
			if second, off2, ok := unpackDNSName(raw, off); ok && len(raw)-off2 == 20 {
				rec.target, rec.target2 = first, second
				for i := range rec.soa {
					rec.soa[i] = binary.BigEndian.Uint32(raw[off2+i*4:])
				}
			}
		}
	case dnsmessage.TypeTXT:
		var chunks [][]byte
		for off := 0; off < len(raw); {
			length := int(raw[off])
			off++
			if length > len(raw)-off {
				return
			}
			chunks = append(chunks, append([]byte(nil), raw[off:off+length]...))
			off += length
		}
		rec.txt = chunks
	case dnsmessage.TypeSRV:
		if len(raw) >= 7 {
			if target, end, ok := unpackDNSName(raw, 6); ok && end == len(raw) {
				rec.priority = binary.BigEndian.Uint16(raw)
				rec.weight = binary.BigEndian.Uint16(raw[2:])
				rec.port = binary.BigEndian.Uint16(raw[4:])
				rec.target = target
			}
		}
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		// DoH JSON and wire responses normally provide Params directly. Parse
		// raw RDATA as well so records from generic fixtures remain semantic
		// and malformed values can still be shown safely by the renderer.
		priority, target, params, _ := parseRawSVCB(rec.rawRData)
		if target != "" {
			rec.priority = priority
			rec.target = target
		}
		if len(params) > 0 {
			rec.params = params
		}
	}
}

func populateRecordFromPresentation(rec *record) {
	fields := strings.Fields(rec.presentation)
	parseUint16 := func(value string) (uint16, bool) {
		parsed, err := strconv.ParseUint(value, 10, 16)
		return uint16(parsed), err == nil
	}
	parseUint32 := func(value string) (uint32, bool) {
		parsed, err := strconv.ParseUint(value, 10, 32)
		return uint32(parsed), err == nil
	}
	name := func(value string) (string, bool) {
		parsed, err := resolver.ParseName(value)
		if err != nil {
			return "", false
		}
		return parsed.String(), true
	}

	switch rec.typ {
	case dnsmessage.TypeNS:
		if len(fields) == 1 {
			rec.target, _ = name(fields[0])
		}
	case dnsmessage.TypeTXT:
		if chunks, ok := parseDNSCharacterStrings(rec.presentation); ok {
			rec.txt = chunks
		} else {
			// Some JSON resolvers omit the presentation quotes for a single
			// TXT character-string. Preserve that response as one chunk.
			rec.txt = [][]byte{[]byte(rec.presentation)}
		}
	case dnsmessage.TypeMX:
		if len(fields) == 2 {
			preference, numberOK := parseUint16(fields[0])
			target, nameOK := name(fields[1])
			if numberOK && nameOK {
				rec.preference, rec.target = preference, target
			}
		}
	case dnsmessage.TypeSOA:
		if len(fields) == 7 {
			primary, primaryOK := name(fields[0])
			mailbox, mailboxOK := name(fields[1])
			values := [5]uint32{}
			valuesOK := true
			for i := range values {
				values[i], valuesOK = parseUint32(fields[i+2])
				if !valuesOK {
					break
				}
			}
			if primaryOK && mailboxOK && valuesOK {
				rec.target, rec.target2, rec.soa = primary, mailbox, values
			}
		}
	case dnsmessage.TypeSRV:
		if len(fields) == 4 {
			priority, priorityOK := parseUint16(fields[0])
			weight, weightOK := parseUint16(fields[1])
			port, portOK := parseUint16(fields[2])
			target, targetOK := name(fields[3])
			if priorityOK && weightOK && portOK && targetOK {
				rec.priority, rec.weight, rec.port, rec.target = priority, weight, port, target
			}
		}
	case dnsTypeCAA:
		flagsText, rest, flagsFieldOK := cutDNSField(rec.presentation)
		tag, valueText, tagFieldOK := cutDNSField(rest)
		flags, flagsOK := parseUint16(flagsText)
		if flagsFieldOK && tagFieldOK && flagsOK && flags <= 255 && len(tag) <= 255 {
			if values, ok := parseDNSCharacterStrings(valueText); ok && len(values) == 1 {
				rec.rawRData = append([]byte{byte(flags), byte(len(tag))}, []byte(tag)...)
				rec.rawRData = append(rec.rawRData, values[0]...)
			}
		}
	}
}

func cutDNSField(text string) (field, rest string, ok bool) {
	text = strings.TrimLeft(text, " \t")
	if text == "" {
		return "", "", false
	}
	end := strings.IndexAny(text, " \t")
	if end < 0 {
		return text, "", true
	}
	return text[:end], strings.TrimLeft(text[end:], " \t"), true
}

func parseDNSCharacterStrings(text string) ([][]byte, bool) {
	var out [][]byte
	for offset := 0; ; {
		for offset < len(text) && (text[offset] == ' ' || text[offset] == '\t') {
			offset++
		}
		if offset == len(text) {
			return out, len(out) > 0
		}
		if text[offset] != '"' {
			return nil, false
		}
		offset++
		var value []byte
		closed := false
		for offset < len(text) {
			if text[offset] == '"' {
				offset++
				closed = true
				break
			}
			if text[offset] != '\\' {
				value = append(value, text[offset])
				offset++
				continue
			}
			offset++
			if offset == len(text) {
				return nil, false
			}
			if offset+3 <= len(text) && text[offset] >= '0' && text[offset] <= '9' && text[offset+1] >= '0' && text[offset+1] <= '9' && text[offset+2] >= '0' && text[offset+2] <= '9' {
				octet, err := strconv.ParseUint(text[offset:offset+3], 10, 8)
				if err != nil {
					return nil, false
				}
				value = append(value, byte(octet))
				offset += 3
				continue
			}
			value = append(value, text[offset])
			offset++
		}
		if !closed || len(value) > 255 {
			return nil, false
		}
		out = append(out, value)
	}
}

func (rec record) semanticKey() string {
	var b strings.Builder
	switch rec.typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		fmt.Fprintf(&b, "%x", []byte(rec.address))
	case dnsmessage.TypeCNAME, dnsmessage.TypeNS:
		if rec.target == "" && rec.presentation != "" {
			return rec.presentation
		}
		b.WriteString(strings.ToLower(rec.target))
	case dnsmessage.TypeTXT:
		if rec.txt == nil && rec.presentation != "" {
			return rec.presentation
		}
		for _, chunk := range rec.txt {
			fmt.Fprintf(&b, "%d:%x,", len(chunk), chunk)
		}
	case dnsmessage.TypeMX:
		if rec.target == "" && rec.presentation != "" {
			return rec.presentation
		}
		fmt.Fprintf(&b, "%d|%s", rec.preference, strings.ToLower(rec.target))
	case dnsmessage.TypeSOA:
		if (rec.target == "" || rec.target2 == "") && rec.presentation != "" {
			return rec.presentation
		}
		fmt.Fprintf(&b, "%s|%s|", strings.ToLower(rec.target), strings.ToLower(rec.target2))
		for _, value := range rec.soa {
			fmt.Fprintf(&b, "%d,", value)
		}
	case dnsmessage.TypeSRV:
		if rec.target == "" && rec.presentation != "" {
			return rec.presentation
		}
		fmt.Fprintf(&b, "%d|%d|%d|%s", rec.priority, rec.weight, rec.port, strings.ToLower(rec.target))
	case dnsTypeCAA:
		if len(rec.rawRData) == 0 && rec.presentation != "" {
			return rec.presentation
		}
		fmt.Fprintf(&b, "%x", rec.rawRData)
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		fmt.Fprintf(&b, "%d|%s|", rec.priority, strings.ToLower(rec.target))
		for _, param := range rec.params {
			fmt.Fprintf(&b, "%d:%d:%x,", param.Key, len(param.Value), param.Value)
		}
	default:
		fmt.Fprintf(&b, "%x", rec.rawRData)
	}
	if b.Len() == 0 {
		b.WriteString(rec.presentation)
	}
	return b.String()
}

// renderValue is the only place that turns semantic record data into terminal
// presentation. DoH JSON text is used only when that protocol did not provide
// parsed fields or generic wire-format RDATA.
func (rec record) renderValue() string {
	fallback := func() string {
		if rec.presentation != "" {
			return safeRecordText(normalizeDOHValue(rec.typ, rec.presentation))
		}
		return "0x" + hex.EncodeToString(rec.rawRData)
	}

	switch rec.typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if len(rec.address) > 0 {
			return rec.address.String()
		}
	case dnsmessage.TypeCNAME, dnsmessage.TypeNS:
		if rec.target != "" {
			return rec.target
		}
	case dnsmessage.TypeTXT:
		if len(rec.txt) == 1 {
			return formatTXTChunk(rec.txt[0])
		}
	case dnsmessage.TypeMX:
		if rec.target != "" {
			return fmt.Sprintf("%d %s", rec.preference, rec.target)
		}
	case dnsmessage.TypeSOA:
		if rec.target != "" && rec.target2 != "" {
			return fmt.Sprintf("%s %s serial=%d refresh=%d retry=%d expire=%d minttl=%d", rec.target, rec.target2, rec.soa[0], rec.soa[1], rec.soa[2], rec.soa[3], rec.soa[4])
		}
	case dnsmessage.TypeSRV:
		if rec.target != "" {
			return fmt.Sprintf("%d %d %d %s", rec.priority, rec.weight, rec.port, rec.target)
		}
	case dnsTypeCAA:
		if len(rec.rawRData) > 0 {
			return formatCAA(rec.rawRData)
		}
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		if rec.target != "" {
			params := make([]dnsmessage.SVCParam, 0, len(rec.params))
			for _, param := range rec.params {
				params = append(params, dnsmessage.SVCParam{Key: dnsmessage.SVCParamKey(param.Key), Value: param.Value})
			}
			return formatSVCBValue(rec.priority, rec.target, params)
		}
	}
	return fallback()
}

func normalizedOwner(host string) string {
	if queryHost, err := dnsQueryHost(host); err == nil {
		return normalizeOwnerPresentation(queryHost)
	}
	return normalizeOwnerPresentation(host)
}

func normalizeOwnerPresentation(owner string) string {
	return strings.ToLower(absoluteName(owner))
}

func safeRecordText(text string) string {
	for _, r := range text {
		if r == '\n' || r == '\t' || r == '\r' || r == '\\' || r == '"' || r < 0x20 || r >= 0x7f && r <= 0x9f {
			return strconv.Quote(text)
		}
	}
	return text
}

func formatCAA(raw []byte) string {
	flags, tag, value, ok := caaFields(raw)
	if !ok {
		return "0x" + hex.EncodeToString(raw)
	}
	return fmt.Sprintf("%d %s %q", flags, safeRecordText(tag), value)
}

func formatSVCBValue(priority uint16, target string, params []dnsmessage.SVCParam) string {
	parts := []string{fmt.Sprintf("%d", priority), target}
	for _, param := range params {
		parts = append(parts, formatSVCParam(param))
	}
	return strings.Join(parts, " ")
}

func svcParamRenderOrder(key uint16) int {
	// This order follows the diagnostic fields rather than the wire key order:
	// address hints stay together and ECH remains easy to find after them.
	switch key {
	case uint16(dnsmessage.SVCParamMandatory):
		return 0
	case uint16(dnsmessage.SVCParamALPN):
		return 1
	case uint16(dnsmessage.SVCParamNoDefaultALPN):
		return 2
	case uint16(dnsmessage.SVCParamPort):
		return 3
	case uint16(dnsmessage.SVCParamIPv4Hint):
		return 4
	case uint16(dnsmessage.SVCParamIPv6Hint):
		return 5
	case uint16(dnsmessage.SVCParamECH):
		return 6
	case uint16(dnsmessage.SVCParamDOHPath):
		return 7
	case uint16(dnsmessage.SVCParamOHTTP):
		return 8
	case uint16(dnsmessage.SVCParamTLSSupportedGroups):
		return 9
	default:
		return 10
	}
}

func formatStructuredSVCParam(param resolver.SVCParam) (label, value string) {
	switch dnsmessage.SVCParamKey(param.Key) {
	case dnsmessage.SVCParamMandatory:
		return "Mandatory", formatSVCBKeyList(param.Value)
	case dnsmessage.SVCParamALPN:
		if value, ok := formatSVCBALPN(param.Value); ok {
			return "ALPN", value
		}
		return "ALPN", formatSVCBBytes(param.Value)
	case dnsmessage.SVCParamNoDefaultALPN:
		if len(param.Value) == 0 {
			return "No default ALPN", "true"
		}
		return "No default ALPN", formatSVCBBytes(param.Value)
	case dnsmessage.SVCParamPort:
		if len(param.Value) == 2 {
			return "Port", strconv.Itoa(int(binary.BigEndian.Uint16(param.Value)))
		}
		return "Port", formatSVCBBytes(param.Value)
	case dnsmessage.SVCParamIPv4Hint:
		if value, ok := formatSVCBHints(param.Value, 4); ok {
			return "IPv4 hints", value
		}
		return "IPv4 hints", formatSVCBBytes(param.Value)
	case dnsmessage.SVCParamIPv6Hint:
		if value, ok := formatSVCBHints(param.Value, 16); ok {
			return "IPv6 hints", value
		}
		return "IPv6 hints", formatSVCBBytes(param.Value)
	case dnsmessage.SVCParamECH:
		// ECH is already an opaque, length-prefixed binary value. Preserve its
		// complete base64 representation; do not expose only a preview.
		return "ECH", base64.StdEncoding.EncodeToString(param.Value)
	case dnsmessage.SVCParamDOHPath:
		return "DoH path", string(param.Value)
	case dnsmessage.SVCParamOHTTP:
		if len(param.Value) == 0 {
			return "OHTTP", "true"
		}
		return "OHTTP", formatSVCBBytes(param.Value)
	case dnsmessage.SVCParamTLSSupportedGroups:
		if value, ok := formatSVCBUint16List(param.Value); ok {
			return "TLS supported groups", value
		}
		return "TLS supported groups", formatSVCBBytes(param.Value)
	default:
		return formatSVCBParamName(param.Key), formatSVCBBytes(param.Value)
	}
}

func formatSVCBParamName(key uint16) string {
	name := dnsmessage.SVCParamKey(key).String()
	// x/net prints unknown SvcParam keys as bare numbers. The key prefix makes
	// those values unambiguous and matches DNS presentation terminology.
	if _, err := strconv.ParseUint(name, 10, 16); err == nil {
		return "key" + name
	}
	return name
}

func formatSVCBBytes(value []byte) string {
	return "0x" + hex.EncodeToString(value)
}

func formatSVCBALPN(value []byte) (string, bool) {
	var values []string
	for offset := 0; offset < len(value); {
		length := int(value[offset])
		offset++
		if length == 0 || length > len(value)-offset {
			return "", false
		}
		values = append(values, string(value[offset:offset+length]))
		offset += length
	}
	if len(values) == 0 {
		return "", false
	}
	return strings.Join(values, ", "), true
}

func formatSVCBUint16List(value []byte) (string, bool) {
	if len(value) == 0 || len(value)%2 != 0 {
		return "", false
	}
	values := make([]string, 0, len(value)/2)
	for offset := 0; offset < len(value); offset += 2 {
		values = append(values, strconv.Itoa(int(binary.BigEndian.Uint16(value[offset:]))))
	}
	return strings.Join(values, ", "), true
}

func formatSVCBHints(value []byte, width int) (string, bool) {
	if len(value) == 0 || len(value)%width != 0 {
		return "", false
	}
	values := make([]string, 0, len(value)/width)
	for offset := 0; offset < len(value); offset += width {
		values = append(values, net.IP(value[offset:offset+width]).String())
	}
	return strings.Join(values, ", "), true
}

func formatSVCBKeyList(value []byte) string {
	if len(value) == 0 || len(value)%2 != 0 {
		return formatSVCBBytes(value)
	}
	keys := make([]string, 0, len(value)/2)
	for offset := 0; offset < len(value); offset += 2 {
		key := binary.BigEndian.Uint16(value[offset:])
		keys = append(keys, formatSVCBKey(key))
	}
	return strings.Join(keys, ", ")
}

func formatSVCBKey(key uint16) string {
	switch dnsmessage.SVCParamKey(key) {
	case dnsmessage.SVCParamMandatory:
		return "mandatory"
	case dnsmessage.SVCParamALPN:
		return "alpn"
	case dnsmessage.SVCParamNoDefaultALPN:
		return "no-default-alpn"
	case dnsmessage.SVCParamPort:
		return "port"
	case dnsmessage.SVCParamIPv4Hint:
		return "ipv4hint"
	case dnsmessage.SVCParamECH:
		return "ech"
	case dnsmessage.SVCParamIPv6Hint:
		return "ipv6hint"
	case dnsmessage.SVCParamDOHPath:
		return "dohpath"
	case dnsmessage.SVCParamOHTTP:
		return "ohttp"
	case dnsmessage.SVCParamTLSSupportedGroups:
		return "tls-supported-groups"
	default:
		return formatSVCBParamName(key)
	}
}

// parseRawSVCB returns as much of a generic SVCB/HTTPS RDATA value as can be
// safely decoded. The final boolean reports whether the complete value is
// well-formed, which lets the renderer retain malformed data as raw hex.
func parseRawSVCB(raw []byte) (priority uint16, target string, params []resolver.SVCParam, ok bool) {
	if len(raw) < 3 {
		return 0, "", nil, false
	}

	// Use the resolver's strict parser for the validity bit. It checks more
	// than framing, including parameter ordering, duplicate keys, reserved
	// keys, and the semantics of known values. The local decode below still
	// recovers a target and any complete parameters for a useful fallback.
	if parsed, err := resolver.ParseSVCBRData(raw); err == nil {
		params = make([]resolver.SVCParam, len(parsed.Params))
		for i, param := range parsed.Params {
			params[i] = resolver.SVCParam{Key: param.Key, Value: append([]byte(nil), param.Value...)}
		}
		return parsed.Priority, parsed.Target.String(), params, true
	}

	priority = binary.BigEndian.Uint16(raw)
	var offset int
	target, offset, ok = unpackDNSName(raw, 2)
	if !ok {
		return priority, "", nil, false
	}
	for offset < len(raw) {
		if len(raw)-offset < 4 {
			return priority, target, params, false
		}
		key := binary.BigEndian.Uint16(raw[offset:])
		length := int(binary.BigEndian.Uint16(raw[offset+2:]))
		offset += 4
		if length > len(raw)-offset {
			return priority, target, params, false
		}
		params = append(params, resolver.SVCParam{Key: key, Value: append([]byte(nil), raw[offset:offset+length]...)})
		offset += length
	}
	// Reaching this point means strict semantic validation failed. Keep the
	// recovered fields for display, but make the caller retain the raw value.
	return priority, target, params, false
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
			alpns = append(alpns, safeRecordText(string(param.Value[i:i+ln])))
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
	wireSize := 1
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
		if ln&0xc0 != 0 || ln > 63 || off+ln > len(raw) {
			return "", 0, false
		}
		wireSize += 1 + ln
		if wireSize > 255 {
			return "", 0, false
		}
		labels = append(labels, dnsLabelPresentation(raw[off:off+ln]))
		off += ln
	}
}

func dnsLabelPresentation(label []byte) string {
	var b strings.Builder
	for _, value := range label {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-' || value == '_' || value >= 0x21 && value <= 0x7e && value != '.' && value != '\\' {
			b.WriteByte(value)
			continue
		}
		fmt.Fprintf(&b, "\\%03d", value)
	}
	return b.String()
}

// resolverTransportSecurity reports protection for the connection to the
// resolver. It intentionally says nothing about DNSSEC: fetch does not
// validate DNSSEC chains locally.
func resolverTransportSecurity(cfg *Config, server *url.URL) string {
	if server == nil {
		return "platform resolver (OS-managed security)"
	}

	// Endpoint is the authoritative representation used by production callers.
	// Derive the result from VerifyTLS instead of the display URL so --insecure
	// is reflected without changing endpoint configuration. An HTTPS transport
	// used by an explicit local test endpoint can intentionally have TLS
	// verification disabled and is therefore plaintext, not unverified TLS.
	if cfg.Endpoint != nil {
		if cfg.Endpoint.VerifyTLS {
			if cfg.Insecure {
				return string(resolver.SecurityUnverifiedEncrypt)
			}
			return string(resolver.SecurityVerifiedEncrypted)
		}
		return string(resolver.SecurityPlaintext)
	}

	// DNSServer remains supported for older internal callers. Account for all
	// resolver URL schemes here; treating only https:// as encrypted would
	// misreport legacy DoT and DoQ configurations.
	scheme := strings.ToLower(server.Scheme)
	switch scheme {
	case "tls", "dot", "quic", "doq", "https":
		if cfg.Insecure {
			return string(resolver.SecurityUnverifiedEncrypt)
		}
		return string(resolver.SecurityVerifiedEncrypted)
	default:
		// UDP, TCP, and plain HTTP expose DNS on the wire. --insecure has no
		// certificate verification to disable for these transports.
		return string(resolver.SecurityPlaintext)
	}
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
	case resolver.TransportSystem:
		return "platform resolver"
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
	renderInspection(p, res)
}

func inspectionTransportSummary(res *result) string {
	if res.tcpFallback && res.transport == "UDP" {
		return "UDP → TCP fallback"
	}
	return res.transport
}

func renderQueryDetails(p *core.Printer, queries []queryResult) {
	if len(queries) == 0 {
		return
	}

	writeInspectionBlankLine(p)
	renderInspectionSection(p, "Queries")
	for _, query := range queries {
		status := "no data"
		switch query.status {
		case queryStatusData:
			status = countPhrase(len(query.records), "record", "records")
		case queryStatusFailed:
			status = "failed"
		}
		parts := []string{status}
		// Keep the fallback immediately after the status so the legacy focused
		// output remains easy to scan, then append the exact responder details.
		if query.tcpFallback {
			parts = append(parts, "UDP → TCP fallback")
		} else if query.transport != "" {
			parts = append(parts, displayTransport(query.transport))
		}
		if query.responder != "" {
			parts = append(parts, query.responder)
		}
		if query.duration > 0 {
			parts = append(parts, formatDuration(query.duration))
		}
		if query.attempts > 0 {
			parts = append(parts, countPhrase(query.attempts, "attempt", "attempts"))
		}
		writeInspectionField(p, query.typ.label, strings.Join(parts, " · "))
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
	if res.platformFallback {
		if res.resolver != "" {
			writeInspectionField(p, "Resolver", res.resolver)
		}
		if len(res.responders) > 0 {
			writeInspectionField(p, "Resolvers", strings.Join(res.responders, ", "))
		}
	} else if len(res.responders) > 1 {
		writeInspectionField(p, "Resolvers", strings.Join(res.responders, ", "))
	} else if res.resolver != "" {
		writeInspectionField(p, "Resolver", res.resolver)
	}
	if transport := inspectionTransportSummary(res); transport != "" {
		writeInspectionField(p, "Transport", transport)
	}
	if res.security != "" {
		writeInspectionField(p, "Transport security", displaySecurity(res.security))
	}
	if res.source != "" {
		writeInspectionField(p, "Source", res.source)
	}
	if res.platformFallback {
		writeInspectionField(p, "Fallback", "platform resolver used for addresses")
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
	if res.tcpFallback && res.transport != "UDP" {
		writeInspectionField(p, "TCP fallback", "used for truncated UDP response")
	}

	if len(res.failures) > 0 {
		writeInspectionBlankLine(p)
		renderInspectionSection(p, "Failures")
		renderFailures(p, res.failures)
	}
	if res.verbosity >= core.VExtraVerbose {
		renderQueryDetails(p, res.queries)
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
		// Keep the complete error as the grouping key. The displayed value is
		// bounded, so a long resolver diagnostic cannot make the output grow
		// without limit while two distinct errors are not accidentally merged
		// because their prefixes happen to match.
		key string
		err string
	}
	groups := make([]failureGroup, 0, len(failures))
	indices := make(map[string]int, len(failures))
	for _, failure := range failures {
		key, errText := failureDiagnostic(failure.err)
		idx, ok := indices[key]
		if !ok {
			indices[key] = len(groups)
			groups = append(groups, failureGroup{key: key, err: errText})
			idx = len(groups) - 1
		}
		groups[idx].labels = append(groups[idx].labels, failure.label)
	}

	// Aggregation normally supplies failures in inspection order. Sort here as
	// well because renderFailures is also used by focused tests and should be
	// deterministic for any input order.
	for i := range groups {
		slices.SortFunc(groups[i].labels, compareInspectionLabels)
	}
	slices.SortFunc(groups, func(a, b failureGroup) int {
		if cmp := compareInspectionLabels(a.labels[0], b.labels[0]); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.key, b.key)
	})

	for _, group := range groups {
		label := strings.Join(group.labels, ", ")
		if allInspectionTypesFailed(group.labels) {
			label = "All record types"
		}
		writeInspectionField(p, label, group.err)
	}
}

func failureDiagnostic(err error) (key, display string) {
	if err == nil {
		return "query failed", "query failed"
	}
	key = err.Error()
	if key == "" {
		return "query failed", "query failed"
	}
	return key, conciseDiagnostic(key)
}

func allInspectionTypesFailed(labels []string) bool {
	if len(labels) != len(inspectTypes) {
		return false
	}
	seen := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		if _, ok := seen[label]; ok {
			return false
		}
		seen[label] = struct{}{}
	}
	for _, typ := range inspectTypes {
		if _, ok := seen[typ.label]; !ok {
			return false
		}
	}
	return true
}

func compareInspectionLabels(a, b string) int {
	rank := func(label string) int {
		for i, typ := range inspectTypes {
			if label == typ.label {
				return i
			}
		}
		return len(inspectTypes)
	}
	if aRank, bRank := rank(a), rank(b); aRank != bRank {
		if aRank < bRank {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
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

func compareRecords(a, b record) int {
	text := func(left, right string) int {
		return strings.Compare(strings.ToLower(left), strings.ToLower(right))
	}
	if a.typ != b.typ {
		return cmp.Compare(a.typ, b.typ)
	}

	switch a.typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if order := bytes.Compare(a.address, b.address); order != 0 {
			return order
		}
	case dnsmessage.TypeCNAME, dnsmessage.TypeNS:
		if order := text(a.target, b.target); order != 0 {
			return order
		}
	case dnsmessage.TypeTXT:
		for i := 0; i < min(len(a.txt), len(b.txt)); i++ {
			if order := bytes.Compare(a.txt[i], b.txt[i]); order != 0 {
				return order
			}
		}
		if order := cmp.Compare(len(a.txt), len(b.txt)); order != 0 {
			return order
		}
	case dnsmessage.TypeMX:
		if order := cmp.Compare(a.preference, b.preference); order != 0 {
			return order
		}
		if order := text(a.target, b.target); order != 0 {
			return order
		}
	case dnsmessage.TypeSOA:
		if order := text(a.owner, b.owner); order != 0 {
			return order
		}
	case dnsmessage.TypeSRV:
		for _, order := range []int{
			cmp.Compare(a.priority, b.priority),
			cmp.Compare(a.weight, b.weight),
			cmp.Compare(a.port, b.port),
			text(a.target, b.target),
		} {
			if order != 0 {
				return order
			}
		}
	case dnsTypeCAA:
		aFlags, aTag, aValue := caaSortFields(a.rawRData)
		bFlags, bTag, bValue := caaSortFields(b.rawRData)
		for _, order := range []int{text(aTag, bTag), cmp.Compare(aFlags, bFlags), bytes.Compare(aValue, bValue)} {
			if order != 0 {
				return order
			}
		}
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		if order := cmp.Compare(a.priority, b.priority); order != 0 {
			return order
		}
		if order := text(a.target, b.target); order != 0 {
			return order
		}
	default:
		if order := bytes.Compare(a.rawRData, b.rawRData); order != 0 {
			return order
		}
	}
	return strings.Compare(a.semanticKey(), b.semanticKey())
}

func caaSortFields(raw []byte) (uint8, string, []byte) {
	if len(raw) < 2 || int(raw[1]) > len(raw)-2 {
		return 0, "", raw
	}
	tagEnd := 2 + int(raw[1])
	return raw[0], string(raw[2:tagEnd]), raw[tagEnd:]
}

func renderSection(p *core.Printer, name string, records []record) {
	if len(records) == 0 {
		return
	}
	records = slices.Clone(records)
	slices.SortFunc(records, func(a, b record) int {
		if order := compareRecords(a, b); order != 0 {
			return order
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
		last := i == len(records)-1
		switch {
		case rec.typ == dnsmessage.TypeTXT && len(rec.txt) > 1:
			renderTXTRecord(p, rec, last)
		case rec.hasComplexRendering():
			renderComplexRecord(p, rec, last)
		default:
			renderRecordLine(p, rec, last)
		}
	}

	p.WriteInfoPrefix()
	p.WriteString("\n")
}

func (rec record) hasComplexRendering() bool {
	switch rec.typ {
	case dnsmessage.TypeMX:
		return rec.target != ""
	case dnsmessage.TypeSRV:
		return rec.target != ""
	case dnsmessage.TypeSOA:
		return rec.target != "" && rec.target2 != ""
	case dnsTypeCAA:
		_, _, _, ok := caaFields(rec.rawRData)
		return ok
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		return rec.target != ""
	default:
		return false
	}
}

// renderComplexRecord keeps the structured fields of complex resource records
// visible. The first line identifies the owner and target (when one exists),
// while the indented fields explain the numeric and type-specific values.
func renderComplexRecord(p *core.Printer, rec record, last bool) {
	writeRecordPrefix(p, last)
	p.Set(core.Green)
	if rec.owner != "" {
		p.WriteString(core.TerminalSafeText(rec.owner))
		if rec.typ == dnsmessage.TypeSVCB || rec.typ == dnsmessage.TypeHTTPS {
			p.WriteString(" ")
		} else if rec.typ != dnsmessage.TypeSOA && rec.typ != dnsTypeCAA {
			p.WriteString(" → ")
		}
	}
	switch rec.typ {
	case dnsmessage.TypeMX:
		p.WriteString(core.TerminalSafeText(rec.target))
	case dnsmessage.TypeSRV:
		p.WriteString(core.TerminalSafeText(rec.target))
		p.WriteString(fmt.Sprintf(":%d", rec.port))
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		p.WriteString(fmt.Sprintf("priority %d → ", rec.priority))
		p.WriteString(core.TerminalSafeText(safeRecordText(rec.target)))
	case dnsmessage.TypeSOA, dnsTypeCAA:
		// These records list their semantic values on indented lines below.
	}
	p.Reset()
	p.WriteString("\n")

	continued := !last
	switch rec.typ {
	case dnsmessage.TypeMX:
		writeRecordDetail(p, "Priority", strconv.FormatUint(uint64(rec.preference), 10), continued)
	case dnsmessage.TypeSRV:
		writeRecordDetail(p, "Priority", strconv.FormatUint(uint64(rec.priority), 10), continued)
		writeRecordDetail(p, "Weight", strconv.FormatUint(uint64(rec.weight), 10), continued)
	case dnsmessage.TypeSOA:
		writeRecordDetail(p, "Primary NS", rec.target, continued)
		writeRecordDetail(p, "Responsible", rec.target2, continued)
		writeRecordDetail(p, "Serial", strconv.FormatUint(uint64(rec.soa[0]), 10), continued)
		writeRecordDetail(p, "Refresh", formatTTL(rec.soa[1]), continued)
		writeRecordDetail(p, "Retry", formatTTL(rec.soa[2]), continued)
		writeRecordDetail(p, "Expire", formatTTL(rec.soa[3]), continued)
		writeRecordDetail(p, "Minimum TTL", formatTTL(rec.soa[4]), continued)
	case dnsTypeCAA:
		flags, tag, value, ok := caaFields(rec.rawRData)
		if !ok {
			renderRecordLine(p, rec, last)
			return
		}
		writeRecordDetail(p, "Flags", strconv.Itoa(int(flags)), continued)
		writeRecordDetail(p, "Tag", tag, continued)
		writeRecordDetail(p, "Value", value, continued)
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		renderServiceBindingDetails(p, rec, continued)
		return
	}
	writeRecordSourceAndTTL(p, rec, continued)
}

// renderServiceBindingDetails expands HTTPS/SVCB parameters into stable,
// human-readable fields. Parameter values stay bytes until this point so the
// renderer can distinguish valid values from malformed or unknown ones.
func renderServiceBindingDetails(p *core.Printer, rec record, continued bool) {
	if rec.priority == 0 {
		writeRecordDetail(p, "Mode", "AliasMode", continued)
	}

	params := slices.Clone(rec.params)
	slices.SortStableFunc(params, func(a, b resolver.SVCParam) int {
		if order := cmp.Compare(svcParamRenderOrder(a.Key), svcParamRenderOrder(b.Key)); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Key, b.Key); order != 0 {
			return order
		}
		return bytes.Compare(a.Value, b.Value)
	})
	for _, param := range params {
		label, value := formatStructuredSVCParam(param)
		writeRecordDetail(p, label, value, continued)
	}

	// A malformed generic RDATA must remain inspectable. Valid responses have
	// already been decoded into Params, but a generic fixture or an unusual
	// provider can still leave only raw bytes available.
	if len(rec.rawRData) > 0 {
		_, _, _, valid := parseRawSVCB(rec.rawRData)
		if !valid {
			writeRecordDetail(p, "Raw RDATA", "0x"+hex.EncodeToString(rec.rawRData), continued)
		}
	}
	writeRecordSourceAndTTL(p, rec, continued)
}

func writeRecordDetail(p *core.Printer, label, value string, continued bool) {
	writeRecordContinuationPrefix(p, continued)
	p.WriteString(label)
	p.WriteString(": ")
	p.WriteString(core.TerminalSafeText(safeRecordText(value)))
	p.WriteString("\n")
}

// writeRecordContinuationPrefix keeps detail lines connected to the record
// branch. Without the vertical continuation, the indentation looks like a
// large gap between the tree marker and the field text.
func writeRecordContinuationPrefix(p *core.Printer, continued bool) {
	p.WriteInfoPrefix()
	if continued {
		p.WriteString("  \u2502  ")
		return
	}
	p.WriteString("     ")
}

func writeRecordSourceAndTTL(p *core.Printer, rec record, continued bool) {
	if rec.source == recordSourcePlatform {
		writeRecordDetail(p, "Source", "platform resolver", continued)
	}
	if rec.hasTTL {
		writeRecordDetail(p, "TTL", formatTTL(rec.ttl), continued)
	} else {
		writeRecordDetail(p, "TTL", "unavailable", continued)
	}
}

func caaFields(raw []byte) (flags uint8, tag, value string, ok bool) {
	if len(raw) < 2 {
		return 0, "", "", false
	}
	tagLen := int(raw[1])
	if tagLen > len(raw)-2 {
		return 0, "", "", false
	}
	return raw[0], string(raw[2 : 2+tagLen]), string(raw[2+tagLen:]), true
}

func formatTXTChunk(chunk []byte) string {
	// strconv.Quote escapes controls, invalid UTF-8, and quotes, so TXT data
	// cannot inject terminal control sequences or output lines.
	return strconv.Quote(string(chunk))
}

// renderTXTRecord renders each TXT character-string on its own line. This
// avoids making adjacent DNS character-strings look like one string with a
// synthetic space between their contents.
func renderTXTRecord(p *core.Printer, rec record, last bool) {
	writeRecordPrefix(p, last)
	p.Set(core.Green)
	if rec.owner != "" {
		p.WriteString(core.TerminalSafeText(rec.owner))
	}
	p.Reset()
	p.WriteString("\n")

	for _, chunk := range rec.txt {
		writeRecordContinuationPrefix(p, !last)
		p.Set(core.Green)
		p.WriteString(formatTXTChunk(chunk))
		p.Reset()
		p.WriteString("\n")
	}

	writeRecordContinuationPrefix(p, !last)
	p.Set(core.Dim)
	if rec.source == recordSourcePlatform {
		p.WriteString("Source: platform resolver; ")
	}
	if rec.hasTTL {
		p.WriteString("TTL: ")
		p.WriteString(formatTTL(rec.ttl))
	} else {
		p.WriteString("TTL: unavailable")
	}
	p.Reset()
	p.WriteString("\n")
}

func renderRecordLine(p *core.Printer, rec record, last bool) {
	writeRecordPrefix(p, last)
	p.Set(core.Green)
	if rec.owner != "" {
		p.WriteString(core.TerminalSafeText(rec.owner))
		p.WriteString(" → ")
	}
	p.WriteString(core.TerminalSafeText(rec.renderValue()))
	p.Reset()
	p.WriteString(" ")
	writeRecordMetadata(p, rec)
	p.WriteString("\n")
}

func writeRecordPrefix(p *core.Printer, last bool) {
	p.WriteInfoPrefix()
	if last {
		p.WriteString("  \u2514\u2500 ")
	} else {
		p.WriteString("  \u251c\u2500 ")
	}
}

func writeRecordMetadata(p *core.Printer, rec record) {
	p.Set(core.Dim)
	p.WriteString("(")
	if rec.source == recordSourcePlatform {
		p.WriteString("platform resolver; ")
	}
	if rec.hasTTL {
		p.WriteString("TTL ")
		p.WriteString(formatTTL(rec.ttl))
	} else {
		p.WriteString("TTL unavailable")
	}
	p.WriteString(")")
	p.Reset()
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
	if ttl == 0 {
		return "0s"
	}

	// DNS TTLs are seconds. Use compact whole-unit components so SOA
	// durations such as expire=604800 are readable as 1w instead of 168h.
	remaining := uint64(ttl)
	units := []struct {
		seconds uint64
		suffix  string
	}{
		{7 * 24 * 60 * 60, "w"},
		{24 * 60 * 60, "d"},
		{60 * 60, "h"},
		{60, "m"},
		{1, "s"},
	}
	var b strings.Builder
	for _, unit := range units {
		if remaining < unit.seconds {
			continue
		}
		count := remaining / unit.seconds
		remaining %= unit.seconds
		fmt.Fprintf(&b, "%d%s", count, unit.suffix)
	}
	return b.String()
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
