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
	resolver       string
	security       string
	records        map[string][]record
	failures       []queryFailure
	duration       time.Duration
	tcpFallback    bool
	ttlUnavailable bool
	silent         bool
}

type queryResult struct {
	label       string
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

// Inspect resolves the configured URL hostname and renders DNS information to
// the printer. It returns a non-zero exit code on failure.
func Inspect(ctx context.Context, p *core.Printer, cfg *Config) int {
	server := cfg.DNSServer
	if cfg.Endpoint != nil {
		server = cfg.Endpoint.URL()
	}
	host := cfg.URL.Hostname()
	if host == "" {
		writeDNSError(p, errors.New("--inspect-dns requires a hostname"))
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
	if ip := net.ParseIP(host); ip != nil {
		target := resolverTarget(server)
		renderIPLiteral(p, host, ip, target.label, time.Since(start))
		p.Flush()
		return 0
	}

	res, err := lookup(ctx, cfg, host, start)
	if err != nil {
		writeDNSError(p, err)
		return 1
	}
	render(p, res)
	partial := len(res.failures) > 0
	if partial {
		core.WriteWarningMsgIf(p, formatPartialWarning(res.failures), res.silent)
	}
	p.Flush()
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
		host:     host,
		resolver: target.label,
		security: resolverSecurity(cfg, server),
		records:  make(map[string][]record),
		silent:   cfg.Silent,
	}

	// A missing --dns-server means the platform resolver, not the first
	// nameserver listed in resolv.conf. The platform API exposes addresses but
	// not per-record TTLs, and it cannot provide the additional record types.
	if server == nil {
		target = resolverTargetInfo{label: "system resolver", useDefault: true}
		out.resolver = target.label
		out.ttlUnavailable = true
	}

	if cfg.Endpoint != nil && cfg.Endpoint.Transport != resolver.TransportUDP && cfg.Endpoint.Transport != resolver.TransportTCP && cfg.Endpoint.Transport != resolver.TransportTLS && cfg.Endpoint.Transport != resolver.TransportQUIC && cfg.Endpoint.Transport != resolver.TransportHTTPS {
		return nil, fmt.Errorf("resolver transport %s is not implemented", cfg.Endpoint.Transport)
	}

	if target.useDefault {
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
	}

	results := make([]queryResult, len(inspectTypes))
	var wg sync.WaitGroup
	for i, qt := range inspectTypes {
		wg.Add(1)
		go func(i int, qt queryType) {
			defer wg.Done()
			results[i].label = qt.label
			if streamClient != nil {
				results[i].records, results[i].err = lookupStreamRecords(ctx, streamClient, host, qt)
				return
			}
			if doqClient != nil {
				results[i].records, results[i].err = lookupDoQRecords(ctx, doqClient, host, qt)
				return
			}
			if dohClient != nil {
				results[i].records, results[i].err = lookupDOHRecordsWithClient(ctx, dohClient, host, qt)
				return
			}
			results[i].records, results[i].tcpFallback, results[i].err = lookupUDPRecordsWithFallback(ctx, target.udpAddr, host, qt)
		}(i, qt)
	}
	wg.Wait()

	var firstErr error
	seen := make(map[string]int)
	for _, query := range results {
		out.tcpFallback = out.tcpFallback || query.tcpFallback
		if query.err != nil && !errors.Is(query.err, resolver.ErrDNSNoData) {
			out.failures = append(out.failures, queryFailure{label: query.label, err: query.err})
			if firstErr == nil {
				firstErr = query.err
			}
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

	if recordCount(out) > 0 || len(out.failures) > 0 {
		return out, nil
	}
	if firstErr != nil {
		return nil, fmt.Errorf("lookup %s: %w", host, firstErr)
	}
	return nil, fmt.Errorf("lookup %s: no DNS records found", host)
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
		return param.Key.String() + "=" + base64.StdEncoding.EncodeToString(param.Value)
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
		return resolverTargetInfo{label: "udp " + server.Host, udpAddr: server.Host}
	default:
		return resolverTargetInfo{label: server.String()}
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

func renderIPLiteral(p *core.Printer, host string, ip net.IP, resolver string, duration time.Duration) {
	p.WriteInfoPrefix()
	p.Set(core.Bold)
	p.Set(core.Cyan)
	p.WriteString("DNS lookup")
	p.Reset()
	p.WriteString(": ")
	p.Set(core.Bold)
	p.WriteString(core.TerminalSafeText(host))
	p.Reset()
	p.WriteString("\n")

	p.WriteInfoPrefix()
	p.WriteString("Resolver: ")
	p.Set(core.Italic)
	p.WriteString(core.TerminalSafeText(resolver))
	p.Reset()
	p.WriteString("\n\n")

	p.WriteInfoPrefix()
	p.WriteString("  IP literal: ")
	p.Set(core.Green)
	p.WriteString(ip.String())
	p.Reset()
	p.WriteString(" (no DNS query needed)\n")

	p.WriteInfoPrefix()
	p.WriteString("  Duration: ")
	p.Set(core.Dim)
	p.WriteString(formatDuration(duration))
	p.Reset()
	p.WriteString("\n")
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

func formatPartialWarning(failures []queryFailure) string {
	parts := make([]string, 0, len(failures))
	for _, failure := range failures {
		if failure.err == nil {
			parts = append(parts, failure.label)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", failure.label, conciseDiagnostic(failure.err.Error())))
	}
	return "DNS inspection incomplete; failed record types: " + strings.Join(parts, ", ")
}

func render(p *core.Printer, res *result) {
	p.WriteInfoPrefix()
	p.Set(core.Bold)
	p.Set(core.Cyan)
	p.WriteString("DNS lookup")
	p.Reset()
	p.WriteString(": ")
	p.Set(core.Bold)
	p.WriteString(core.TerminalSafeText(res.host))
	p.Reset()
	p.WriteString("\n")

	p.WriteInfoPrefix()
	p.WriteString("Resolver: ")
	p.Set(core.Italic)
	p.WriteString(core.TerminalSafeText(res.resolver))
	p.Reset()
	p.WriteString("\n")
	p.WriteInfoPrefix()
	p.WriteString("Security: ")
	p.WriteString(core.TerminalSafeText(res.security))
	p.WriteString("\n")
	if res.ttlUnavailable {
		p.WriteInfoPrefix()
		p.WriteString("TTL: unavailable (platform resolver does not provide per-record TTLs)\n")
	}
	if res.tcpFallback {
		core.WriteWarningMsgIf(p, "UDP response was truncated; used TCP fallback", res.silent)
	}
	p.WriteInfoPrefix()
	p.WriteString("\n")

	for _, qt := range inspectTypes {
		renderSection(p, qt.label, res.records[qt.label])
	}
	renderOtherSections(p, res.records)

	p.WriteInfoPrefix()
	p.WriteString("  Addresses: ")
	p.Set(core.Bold)
	p.WriteString(fmt.Sprintf("%d", len(res.records["A"])+len(res.records["AAAA"])))
	p.Reset()
	p.WriteString("\n")

	p.WriteInfoPrefix()
	p.WriteString("  Records: ")
	p.Set(core.Bold)
	p.WriteString(fmt.Sprintf("%d", recordCount(res)))
	p.Reset()
	p.WriteString("\n")

	p.WriteInfoPrefix()
	p.WriteString("  Duration: ")
	p.Set(core.Dim)
	p.WriteString(formatDuration(res.duration))
	p.Reset()
	p.WriteString("\n")
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
		if rec.hasTTL {
			p.WriteString(" ")
			p.Set(core.Dim)
			p.WriteString("(TTL ")
			p.WriteString(formatTTL(rec.ttl))
			p.WriteString(")")
			p.Reset()
		}
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

func writeDNSError(p *core.Printer, err error) {
	core.WriteErrorMsgNoFlush(p, err)
	p.Flush()
}
