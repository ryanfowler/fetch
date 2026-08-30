package dnsinspect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/resolver"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"
)

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
	if cfg.Endpoint != nil {
		out.resolverBootstrap = endpointBootstrapDescription(cfg.Endpoint)
	}

	// A missing --dns-server prefers the resolv.conf nameservers, which expose
	// every record type and per-record TTLs. The platform API is only the
	// fallback: it surfaces A/AAAA and no per-record TTLs.
	systemDefault := server == nil
	var systemPolicy *resolver.SystemResolverPolicy
	if systemDefault {
		policy := loadSystemResolverPolicy(cfg)
		if policy != nil && len(policy.Nameservers) > 0 {
			setSystemResolverDetails(out, *policy)
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
	queryTransport := resolver.TransportUDP
	if cfg.Endpoint != nil {
		queryTransport = cfg.Endpoint.Transport
	} else if server != nil {
		queryTransport = resolverURLTransport(server)
	}
	queryResponder := target.label
	if target.udpAddr != "" {
		queryResponder = target.udpAddr
	}
	results := runFanOut(queryCtx, queryHost, target, systemPolicy, queryTransport, queryResponder, streamClient, doqClient, dohClient)
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
func runFanOut(ctx context.Context, host string, target resolverTargetInfo, systemPolicy *resolver.SystemResolverPolicy, queryTransport resolver.Transport, queryResponder string, streamClient *resolver.StreamClient, doqClient *resolver.DoQClient, dohClient *resolver.DOHClient) []queryResult {
	results := make([]queryResult, len(inspectTypes))
	var wg sync.WaitGroup
	for i, qt := range inspectTypes {
		wg.Add(1)
		go func(i int, qt queryType) {
			defer wg.Done()
			queryStart := time.Now()
			results[i].typ = qt
			if systemPolicy == nil {
				// Explicit resolver backends do not return QueryMetadata, but their
				// transport is known before the query starts. Set the responder only
				// after a query succeeds; an endpoint is not proof that it answered.
				results[i].transport = queryTransport
			}
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
			if systemPolicy == nil && results[i].err == nil {
				results[i].responder = queryResponder
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

	// DNS wire names are absolute. Keep the trailing root label in the
	// inspection result so it describes the name sent to a raw resolver. The
	// resolver parser also enforces the DNS label and total-name size limits
	// after IDNA expansion.
	queryName := strings.Join(labels, ".") + "."
	if _, err := resolver.ParseName(queryName); err != nil {
		return "", err
	}
	return queryName, nil
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
		host:                    orig.host,
		queryName:               orig.queryName,
		resolver:                "system nameservers + platform resolver",
		transport:               "mixed",
		security:                "mixed",
		source:                  "system resolver configuration + platform resolver",
		responders:              append(slices.Clone(orig.responders), "platform resolver"),
		records:                 make(map[string][]record, len(orig.records)),
		queries:                 slices.Clone(orig.queries),
		failures:                slices.Clone(orig.failures),
		queryTotal:              orig.queryTotal,
		queryWithData:           orig.queryWithData,
		queryNoData:             orig.queryNoData,
		tcpFallback:             orig.tcpFallback,
		platformFallback:        true,
		verbosity:               orig.verbosity,
		configuredNameservers:   slices.Clone(orig.configuredNameservers),
		resolverAttempts:        orig.resolverAttempts,
		resolverTimeout:         orig.resolverTimeout,
		resolverRotation:        orig.resolverRotation,
		resolverConfiguration:   orig.resolverConfiguration,
		resolverRouting:         orig.resolverRouting,
		resolverSearchDomains:   orig.resolverSearchDomains,
		resolverOSRouting:       orig.resolverOSRouting,
		resolverPlatformRouting: orig.resolverPlatformRouting,
		resolverBootstrap:       orig.resolverBootstrap,
		duration:                time.Since(start),
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
	seen := make(map[string]struct{}, len(addrs))
	owner := normalizedOwner(host)
	for _, addr := range addrs {
		ip := addr.IP
		var rec record
		switch {
		case ip.To4() != nil:
			rec = record{owner: owner, typ: dnsmessage.TypeA, address: append(net.IP(nil), ip.To4()...), source: recordSourcePlatform}
		case ip.To16() != nil:
			rec = record{owner: owner, typ: dnsmessage.TypeAAAA, address: append(net.IP(nil), ip.To16()...), zone: addr.Zone, source: recordSourcePlatform}
		default:
			continue
		}
		key := strconv.Itoa(int(rec.typ)) + "\x00" + rec.semanticKey()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		records = append(records, rec)
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

// isIPLiteral reports IPv4, IPv6, and scoped IPv6 literals. URL.Hostname
// removes brackets from IPv6 authorities and decodes the zone separator, so
// check the address without its optional interface zone. A scoped IPv6
// literal is still an address that must not trigger DNS inspection.
func isIPLiteral(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if zone := strings.IndexByte(host, '%'); zone > 0 && zone+1 < len(host) {
		ip := net.ParseIP(host[:zone])
		// A zone is valid only on an IPv6 spelling. IPv4-mapped IPv6
		// addresses retain the colon syntax even though To4 reports true.
		return ip != nil && strings.Contains(host[:zone], ":")
	}
	return false
}
