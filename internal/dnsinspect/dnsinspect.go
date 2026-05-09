package dnsinspect

import (
	"context"
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
	DNSServer *url.URL
	Timeout   time.Duration
	URL       *url.URL
}

type queryType struct {
	label   string
	dohType string
	dnsType dnsmessage.Type
}

type record struct {
	typ   string
	value string
	ttl   uint32
}

type result struct {
	host     string
	resolver string
	records  map[string][]record
	duration time.Duration
}

type queryResult struct {
	records []record
	err     error
}

// Inspect resolves the configured URL hostname and renders DNS information to
// the printer. It returns a non-zero exit code on failure.
func Inspect(ctx context.Context, p *core.Printer, cfg *Config) int {
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
		resolver, _ := resolverTarget(cfg.DNSServer)
		renderIPLiteral(p, host, ip, resolver, time.Since(start))
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
	resolverLabel, udpAddr := resolverTarget(cfg.DNSServer)
	out := &result{
		host:     host,
		resolver: resolverLabel,
		records:  make(map[string][]record),
	}

	results := make([]queryResult, len(inspectTypes))
	var wg sync.WaitGroup
	for i, qt := range inspectTypes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if cfg.DNSServer != nil && cfg.DNSServer.Scheme != "" {
				results[i].records, results[i].err = lookupDOHRecords(ctx, cfg.DNSServer, host, qt)
				return
			}
			results[i].records, results[i].err = lookupUDPRecords(ctx, udpAddr, host, qt)
		}()
	}
	wg.Wait()

	var firstErr error
	seen := make(map[string]int)
	for _, result := range results {
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

func lookupDOHRecords(ctx context.Context, serverURL *url.URL, host string, qt queryType) ([]record, error) {
	type answer struct {
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

	var res response
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	if res.Status != 0 {
		name := rcodeName(res.Status)
		if name == "" {
			return nil, errors.New("no DNS records found")
		}
		return nil, fmt.Errorf("no DNS records found: %s", name)
	}

	records := make([]record, 0, len(res.Answer))
	for _, answer := range res.Answer {
		typ := dnsmessage.Type(answer.Type)
		label := typeLabel(typ)
		records = append(records, record{
			typ:   label,
			value: normalizeDOHValue(typ, answer.Data),
			ttl:   answer.TTL,
		})
	}
	return records, nil
}

func lookupUDPRecords(ctx context.Context, serverAddr, host string, qt queryType) ([]record, error) {
	name, err := dnsmessage.NewName(absoluteName(host))
	if err != nil {
		return nil, err
	}

	id := uint16(time.Now().UnixNano())
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  qt.dnsType,
			Class: dnsmessage.ClassINET,
		}},
	}
	raw, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(raw); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	var res dnsmessage.Message
	if err := res.Unpack(buf[:n]); err != nil {
		return nil, err
	}
	if res.Header.ID != id {
		return nil, errors.New("mismatched DNS response ID")
	}
	if res.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("no DNS records found: %s", res.Header.RCode.String())
	}
	if res.Header.Truncated {
		return nil, errors.New("DNS response was truncated")
	}

	records := make([]record, 0, len(res.Answers))
	for _, answer := range res.Answers {
		rec, ok := resourceRecord(answer)
		if ok {
			records = append(records, rec)
		}
	}
	return records, nil
}

func resourceRecord(res dnsmessage.Resource) (record, bool) {
	value, ok := resourceValue(res)
	if !ok {
		return record{}, false
	}
	return record{
		typ:   typeLabel(res.Header.Type),
		value: value,
		ttl:   res.Header.TTL,
	}, true
}

func resourceValue(res dnsmessage.Resource) (string, bool) {
	switch body := res.Body.(type) {
	case *dnsmessage.AResource:
		return net.IP(body.A[:]).String(), true
	case *dnsmessage.AAAAResource:
		return net.IP(body.AAAA[:]).String(), true
	case *dnsmessage.CNAMEResource:
		return body.CNAME.String(), true
	case *dnsmessage.TXTResource:
		return strings.Join(body.TXT, " "), true
	case *dnsmessage.MXResource:
		return fmt.Sprintf("%d %s", body.Pref, body.MX.String()), true
	case *dnsmessage.NSResource:
		return body.NS.String(), true
	case *dnsmessage.SOAResource:
		return fmt.Sprintf("%s %s serial=%d refresh=%d retry=%d expire=%d minttl=%d",
			body.NS.String(), body.MBox.String(), body.Serial, body.Refresh, body.Retry, body.Expire, body.MinTTL), true
	case *dnsmessage.SRVResource:
		return fmt.Sprintf("%d %d %d %s", body.Priority, body.Weight, body.Port, body.Target.String()), true
	case *dnsmessage.SVCBResource:
		return formatSVCB(body.Priority, body.Target, body.Params), true
	case *dnsmessage.HTTPSResource:
		return formatSVCB(body.Priority, body.Target, body.Params), true
	case *dnsmessage.UnknownResource:
		if res.Header.Type == dnsTypeCAA {
			return formatCAA(body.Data), true
		}
		return "0x" + hex.EncodeToString(body.Data), true
	default:
		return "", false
	}
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

func formatSVCB(priority uint16, target dnsmessage.Name, params []dnsmessage.SVCParam) string {
	return formatSVCBValue(priority, target.String(), params)
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

func resolverTarget(server *url.URL) (label, udpAddr string) {
	switch {
	case server == nil:
		addr := systemDNSServer()
		return "system (" + addr + ")", addr
	case server.Scheme == "":
		return "udp " + server.Host, server.Host
	default:
		return server.String(), ""
	}
}

func systemDNSServer() string {
	raw, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "nameserver" {
				return net.JoinHostPort(fields[1], "53")
			}
		}
	}
	return net.JoinHostPort("127.0.0.1", "53")
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
	p.WriteString(host)
	p.Reset()
	p.WriteString("\n")

	p.WriteInfoPrefix()
	p.WriteString("Resolver: ")
	p.Set(core.Italic)
	p.WriteString(resolver)
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
	p.WriteString(res.host)
	p.Reset()
	p.WriteString("\n")

	p.WriteInfoPrefix()
	p.WriteString("Resolver: ")
	p.Set(core.Italic)
	p.WriteString(res.resolver)
	p.Reset()
	p.WriteString("\n")
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
		p.WriteString(rec.value)
		p.Reset()
		p.WriteString(" ")
		p.Set(core.Dim)
		p.WriteString("(TTL ")
		p.WriteString(formatTTL(rec.ttl))
		p.WriteString(")")
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

func writeDNSError(p *core.Printer, err error) {
	core.WriteErrorMsgNoFlush(p, err)
	p.Flush()
}
