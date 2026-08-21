package dnsinspect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

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
	Endpoint  *resolver.Endpoint
	DNSServer *url.URL
	CACerts   []*x509.Certificate
	TLSConfig *tls.Config
	Insecure  bool
	TLSMin    uint16
	TLSMax    uint16
	Timeout   time.Duration
	URL       *url.URL
	Silent    bool
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
	host        string
	resolver    string
	records     map[string][]record
	duration    time.Duration
	tcpFallback bool
	silent      bool
}

type queryResult struct {
	records     []record
	err         error
	tcpFallback bool
}

type resolverTargetInfo struct {
	label      string
	udpAddr    string
	useDefault bool
}

var (
	readResolvConf      = func() ([]byte, error) { return os.ReadFile("/etc/resolv.conf") }
	defaultLookupIPAddr = net.DefaultResolver.LookupIPAddr
)

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

	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

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
	p.Flush()
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
		records:  make(map[string][]record),
		silent:   cfg.Silent,
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
	var err error
	if cfg.Endpoint != nil && (cfg.Endpoint.Transport == resolver.TransportTCP || cfg.Endpoint.Transport == resolver.TransportTLS) {
		streamClient, err = resolver.NewStreamClient(ctx, resolver.StreamConfig{
			Endpoint:  cfg.Endpoint,
			TLSConfig: cfg.TLSConfig,
			CACerts:   cfg.CACerts,
			Insecure:  cfg.Insecure,
			TLSMin:    cfg.TLSMin,
			TLSMax:    cfg.TLSMax,
		})
		if err != nil {
			return nil, fmt.Errorf("connect to resolver: %w", err)
		}
		defer streamClient.Close()
	}
	if cfg.Endpoint != nil && cfg.Endpoint.Transport == resolver.TransportQUIC {
		doqClient, err = resolver.NewDoQClient(ctx, resolver.DoQConfig{
			Endpoint:  cfg.Endpoint,
			TLSConfig: cfg.TLSConfig,
			CACerts:   cfg.CACerts,
			Insecure:  cfg.Insecure,
			TLSMin:    cfg.TLSMin,
			TLSMax:    cfg.TLSMax,
		})
		if err != nil {
			return nil, fmt.Errorf("connect to resolver: %w", err)
		}
		defer doqClient.Close()
	}

	results := make([]queryResult, len(inspectTypes))
	var wg sync.WaitGroup
	for i, qt := range inspectTypes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if streamClient != nil {
				results[i].records, results[i].err = lookupStreamRecords(ctx, streamClient, host, qt)
				return
			}
			if doqClient != nil {
				results[i].records, results[i].err = lookupDoQRecords(ctx, doqClient, host, qt)
				return
			}
			if server != nil && server.Scheme != "" {
				results[i].records, results[i].err = lookupDOHRecords(ctx, server, host, qt)
				return
			}
			results[i].records, results[i].tcpFallback, results[i].err = lookupUDPRecordsWithFallback(ctx, target.udpAddr, host, qt)
		}()
	}
	wg.Wait()

	var firstErr error
	seen := make(map[string]int)
	for _, result := range results {
		out.tcpFallback = out.tcpFallback || result.tcpFallback
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
		for _, rec := range result.records {
			key := rec.typ + "\x00" + rec.value
			if idx, ok := seen[key]; ok {
				records := out.records[rec.typ]
				if rec.ttl < records[idx].ttl {
					records[idx].ttl = rec.ttl
				}
				continue
			}
			seen[key] = len(out.records[rec.typ])
			out.records[rec.typ] = append(out.records[rec.typ], rec)
		}
	}
	out.duration = time.Since(start)

	if recordCount(out) > 0 {
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

func lookupDOHRecords(ctx context.Context, serverURL *url.URL, host string, qt queryType) ([]record, error) {
	if message, err := resolver.LookupDOHWireMessage(ctx, serverURL, host, int(qt.dnsType)); err == nil {
		name, parseErr := resolver.ParseName(host)
		if parseErr != nil {
			return nil, parseErr
		}
		authorized, authErr := resolver.AuthorizeAnswers(message, resolver.Question{Name: name, Type: uint16(qt.dnsType), Class: 1})
		if authErr != nil {
			return nil, authErr
		}
		out := make([]record, 0, len(authorized))
		for _, answer := range authorized {
			value, ok := wireRecordValue(answer)
			if ok {
				out = append(out, record{typ: typeLabel(dnsmessage.Type(answer.Type)), value: value, ttl: answer.TTL, hasTTL: true})
			}
		}
		return out, nil
	} else if !errors.Is(err, resolver.ErrDOHProtocolIncompatible) {
		return nil, err
	}
	type answer struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
		TTL  uint32 `json:"TTL"`
	}
	type response struct {
		Status int      `json:"Status"`
		Answer []answer `json:"Answer"`
	}

	u := *serverURL
	q := u.Query()
	q.Set("name", host)
	q.Set("type", qt.dohType)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", core.UserAgent)

	var client http.Client
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
		if err != nil {
			return nil, fmt.Errorf("http response code: %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, raw)
	}

	rawJSON, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(rawJSON) > 1<<20 {
		return nil, errors.New("DoH JSON response exceeds the 1 MiB limit")
	}
	var res response
	if err := json.Unmarshal(rawJSON, &res); err != nil {
		return nil, err
	}
	if res.Status != 0 {
		name := rcodeName(res.Status)
		if name == "" {
			return nil, errors.New("no DNS records found")
		}
		return nil, fmt.Errorf("no DNS records found: %s", name)
	}

	qname, err := resolver.ParseName(host)
	if err != nil {
		return nil, err
	}
	question := resolver.Question{Name: qname, Type: uint16(qt.dnsType), Class: 1}
	message := &resolver.Message{Answers: make([]resolver.Record, 0, len(res.Answer))}
	owners := make([]resolver.Name, len(res.Answer))
	for i, answer := range res.Answer {
		owner := qname
		if answer.Name != "" {
			owner, err = resolver.ParseName(answer.Name)
			if err != nil {
				return nil, fmt.Errorf("invalid DoH JSON answer owner: %w", err)
			}
		}
		owners[i] = owner
		rr := resolver.Record{Owner: owner, Type: uint16(answer.Type), Class: 1, TTL: answer.TTL}
		raw, generic := parseGenericRDATA(answer.Data)
		if strings.HasPrefix(strings.TrimSpace(answer.Data), `\#`) && !generic {
			return nil, errors.New("invalid DoH JSON generic RDATA")
		}
		if generic {
			if err := resolver.ValidateRData(uint16(answer.Type), raw); err != nil {
				return nil, fmt.Errorf("invalid DoH JSON RDATA: %w", err)
			}
			rr.RData = raw
		}
		switch answer.Type {
		case int(dnsmessage.TypeA), int(dnsmessage.TypeAAAA):
			if generic {
				break
			}
			ip := net.ParseIP(answer.Data)
			if ip == nil || (answer.Type == int(dnsmessage.TypeA) && ip.To4() == nil) || (answer.Type == int(dnsmessage.TypeAAAA) && (ip.To16() == nil || ip.To4() != nil)) {
				return nil, errors.New("invalid DoH JSON address")
			}
			if answer.Type == int(dnsmessage.TypeA) {
				rr.RData = append([]byte(nil), ip.To4()...)
			} else {
				rr.RData = append([]byte(nil), ip.To16()...)
			}
		case int(dnsmessage.TypeCNAME):
			target, parseErr := resolver.ParseName(answer.Data)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid DoH JSON CNAME: %w", parseErr)
			}
			rr.Target = &target
		}
		message.Answers = append(message.Answers, rr)
	}
	authorized, err := resolver.AuthorizeAnswers(message, question)
	if err != nil {
		return nil, err
	}
	records := make([]record, 0, len(res.Answer))
	for i, answer := range res.Answer {
		allowed := false
		for _, rr := range authorized {
			if rr.Owner.Equal(owners[i]) {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		typ := dnsmessage.Type(answer.Type)
		label := typeLabel(typ)
		records = append(records, record{typ: label, value: normalizeDOHValue(typ, answer.Data), ttl: answer.TTL, hasTTL: true})
	}
	return records, nil
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

func resolverTarget(server *url.URL) resolverTargetInfo {
	switch {
	case server == nil:
		addr, ok := systemDNSServer()
		if !ok {
			return resolverTargetInfo{label: "system resolver", useDefault: true}
		}
		return resolverTargetInfo{label: "system (" + addr + ")", udpAddr: addr}
	case server.Scheme == "":
		return resolverTargetInfo{label: "udp " + server.Host, udpAddr: server.Host}
	default:
		return resolverTargetInfo{label: server.String()}
	}
}

func systemDNSServer() (string, bool) {
	raw, err := readResolvConf()
	if err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "nameserver" {
				return net.JoinHostPort(fields[1], "53"), true
			}
		}
	}
	return "", false
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

func rcodeName(status int) string {
	switch status {
	case 1:
		return "FormatError"
	case 2:
		return "ServerFailure"
	case 3:
		return "NXDomain"
	case 4:
		return "NotImplemented"
	case 5:
		return "Refused"
	default:
		return ""
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
