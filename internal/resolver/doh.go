package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
)

// DOHConfig controls one DNS-over-HTTPS client. RoundTripper and DialContext
// are intentionally injectable: the application can provide its proxy and
// resolver-aware dial policy without duplicating DoH parsing and validation.
type DOHConfig struct {
	Endpoint     *Endpoint
	ServerURL    *url.URL
	RoundTripper http.RoundTripper
	// RoundTripperOwned transfers responsibility for closing RoundTripper to
	// the returned client. Callers that inject a shared transport must leave
	// this false.
	RoundTripperOwned bool
	Proxy             func(*http.Request) (*url.URL, error)
	DialContext       DialContextFunc
	Bootstrap         BootstrapFunc
	TLSConfig         *tls.Config
	CACerts           []*x509.Certificate
	ClientCert        *tls.Certificate
	Insecure          bool
	TLSMin            uint16
	TLSMax            uint16
	Timeout           time.Duration
}

// DOHClient keeps one HTTP client, and therefore its connection pool, for a
// related set of DNS queries. It is safe for concurrent Lookup calls.
type DOHClient struct {
	client         *http.Client
	serverURL      *url.URL
	timeout        time.Duration
	ownedTransport bool
	closeOnce      sync.Once
}

// NewDOHClient creates an operation-scoped DoH client. It does not follow
// redirects: a redirect changes the resolver endpoint protocol and must not
// silently turn a failed wire request into an unrelated request.
func NewDOHClient(cfg DOHConfig) (*DOHClient, error) {
	serverURL := cfg.ServerURL
	if serverURL == nil && cfg.Endpoint != nil {
		serverURL = cfg.Endpoint.URL()
	}
	if serverURL == nil || serverURL.Host == "" {
		return nil, errors.New("DoH endpoint is missing")
	}
	if err := core.ValidateTLSVersions(cfg.TLSMin, cfg.TLSMax); err != nil {
		return nil, err
	}
	if cfg.TLSConfig != nil {
		if err := core.ValidateTLSVersions(cfg.TLSConfig.MinVersion, cfg.TLSConfig.MaxVersion); err != nil {
			return nil, err
		}
	}
	if !strings.EqualFold(serverURL.Scheme, "https") && !strings.EqualFold(serverURL.Scheme, "http") {
		return nil, fmt.Errorf("DoH endpoint has unsupported scheme %q", serverURL.Scheme)
	}
	serverURL = cloneURL(serverURL)

	transport := cfg.RoundTripper
	ownedTransport := transport == nil || cfg.RoundTripperOwned
	if transport == nil {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			base = &http.Transport{}
		} else {
			base = base.Clone()
		}
		base.ForceAttemptHTTP2 = true
		base.Proxy = cfg.Proxy
		if serverURL.Scheme == "https" {
			base.TLSClientConfig = dohTLSConfig(cfg, serverURL.Hostname())
		}
		dial := cfg.DialContext
		if dial == nil {
			var d net.Dialer
			dial = d.DialContext
		}
		base.DialContext = dohDialContext(dial, cfg.Bootstrap, cfg.Endpoint, serverURL)
		transport = base
	}

	return &DOHClient{
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		serverURL:      serverURL,
		timeout:        cfg.Timeout,
		ownedTransport: ownedTransport,
	}, nil
}

// Close releases idle connections from the transport owned by the DoH client.
// A transport supplied by the caller remains the caller's responsibility.
// Close is safe to call more than once.
func (c *DOHClient) Close() error {
	if c == nil {
		return nil
	}
	var closeErr error
	c.closeOnce.Do(func() {
		if !c.ownedTransport || c.client == nil {
			return
		}
		if idleCloser, ok := c.client.Transport.(interface{ CloseIdleConnections() }); ok {
			idleCloser.CloseIdleConnections()
		}
		if closer, ok := c.client.Transport.(io.Closer); ok {
			closeErr = closer.Close()
		}
	})
	return closeErr
}

func cloneURL(u *url.URL) *url.URL {
	copyURL := *u
	return &copyURL
}

func dohTLSConfig(cfg DOHConfig, serverName string) *tls.Config {
	return core.BuildTLSConfig(core.TLSConfigOptions{
		Base:       cfg.TLSConfig,
		CACerts:    cfg.CACerts,
		ClientCert: cfg.ClientCert,
		Insecure:   cfg.Insecure,
		TLSMax:     cfg.TLSMax,
		TLSMin:     cfg.TLSMin,
		ServerName: serverName,
		NextProtos: []string{"h2", "http/1.1"},
	})
}

func dohDialContext(dial DialContextFunc, bootstrap BootstrapFunc, endpoint *Endpoint, serverURL *url.URL) DialContextFunc {
	endpointHost := strings.TrimSuffix(serverURL.Hostname(), ".")
	var bootstrapAddrs []net.IPAddr
	if endpoint != nil {
		for _, ip := range endpoint.BootstrapAddrs {
			bootstrapAddrs = append(bootstrapAddrs, net.IPAddr{IP: append(net.IP(nil), ip...)})
		}
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(strings.TrimSuffix(host, "."), endpointHost) {
			// The DoH endpoint must be bootstrapped without using itself. This
			// also covers the configured proxy address: a custom DoH resolver
			// cannot resolve that address until its own connection exists, so
			// the base dialer is the deliberate, narrow bootstrap exception.
			return dial(ctx, network, address)
		}
		addresses := bootstrapAddrs
		if len(addresses) == 0 && bootstrap != nil && net.ParseIP(host) == nil {
			addresses, err = bootstrap(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("resolve DoH endpoint %q: %w", host, err)
			}
		}
		if len(addresses) == 0 {
			return dial(ctx, network, address)
		}
		var lastErr error
		for _, ip := range addresses {
			conn, dialErr := dial(ctx, network, core.JoinIPHostPort(ip, port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = errors.New("no DoH endpoint bootstrap addresses")
		}
		return nil, lastErr
	}
}

func lookupDOHClient(ctx context.Context, client *DOHClient, host string) ([]net.IPAddr, error) {
	return resolveAddressFamilies(ctx, func(ctx context.Context, typ uint16) ([]net.IPAddr, error) {
		dnsType := "A"
		if typ == dnsTypeAAAA {
			dnsType = "AAAA"
		}
		records, err := client.LookupType(ctx, host, dnsType, int(typ))
		if err != nil {
			return nil, err
		}
		addrs := make([]net.IPAddr, 0, len(records))
		for _, record := range records {
			addrs = append(addrs, net.IPAddr{IP: record.IP})
		}
		if len(addrs) == 0 {
			return nil, errDNSNoData
		}
		return addrs, nil
	})
}

// DNSRecord is a resolved DNS answer with optional TTL metadata.
type DNSRecord struct {
	IP         net.IP
	TTL        int
	TTLPresent bool
}

// ErrDOHProtocolIncompatible indicates that a DoH endpoint clearly does not
// implement RFC 8484 wire messages. Only this error permits JSON fallback.
var ErrDOHProtocolIncompatible = errors.New("DoH endpoint does not support DNS wire messages")

func (c *DOHClient) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = core.DefaultDOHTimeout
	}
	deadline := time.Now().Add(timeout)
	if existing, ok := ctx.Deadline(); ok && !deadline.Before(existing) {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, deadline)
}

func (c *DOHClient) wireMessage(ctx context.Context, host string, answerType int) (*Message, error) {
	if answerType <= 0 || answerType > 0xffff {
		return nil, fmt.Errorf("invalid DoH query type %d", answerType)
	}
	qname, err := ParseName(host)
	if err != nil {
		return nil, err
	}
	query, id, err := EncodeQuery(host, uint16(answerType))
	if err != nil {
		return nil, err
	}
	question := Question{Name: qname, Type: uint16(answerType), Class: 1}
	requestCtx, cancel := c.operationContext(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.serverURL.String(), bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("User-Agent", core.UserAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if resp.StatusCode != http.StatusOK {
		if dohProtocolIncompatibleStatus(resp.StatusCode) {
			return nil, ErrDOHProtocolIncompatible
		}
		excerpt, excerptErr := readDOHExcerpt(resp.Body)
		if excerptErr == nil && excerpt != "" {
			return nil, fmt.Errorf("DoH response code: %d: %s", resp.StatusCode, core.TerminalSafeText(excerpt))
		}
		return nil, fmt.Errorf("DoH response code: %d", resp.StatusCode)
	}
	if contentType != "application/dns-message" {
		return nil, ErrDOHProtocolIncompatible
	}
	if resp.ContentLength > core.MaxDOHWireResponseBytes {
		return nil, core.LimitError{Subsystem: "DoH wire response", Limit: core.MaxDOHWireResponseBytes}
	}
	raw, err := core.ReadAllLimited(resp.Body, core.MaxDOHWireResponseBytes, "DoH wire response")
	if err != nil {
		return nil, err
	}
	message, err := DecodeResponse(raw, id, question)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH wire response: %w", err)
	}
	if message.Header.RCode != 0 {
		return nil, fmt.Errorf("DoH response: %s", RCodeName(message.Header.RCode))
	}
	if _, err := AuthorizeAnswers(message, question); err != nil {
		return nil, err
	}
	adjustMessageTTLs(message, parseAge(resp.Header.Get("Age")))
	return message, nil
}

func dohProtocolIncompatibleStatus(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusNotImplemented,
		http.StatusMethodNotAllowed, http.StatusNotAcceptable, http.StatusUnsupportedMediaType:
		return true
	default:
		return false
	}
}

func lookupDOHWireMessage(ctx context.Context, serverURL *url.URL, host string, answerType int) (*Message, error) {
	client, err := NewDOHClient(DOHConfig{ServerURL: serverURL})
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.wireMessage(ctx, host, answerType)
}

// LookupDOHWireMessage performs one strict RFC 8484 query. It is used by DNS
// inspection so wire and address-resolution paths share validation.
func LookupDOHWireMessage(ctx context.Context, serverURL *url.URL, host string, answerType int) (*Message, error) {
	return lookupDOHWireMessage(ctx, serverURL, host, answerType)
}

func (c *DOHClient) lookupWireType(ctx context.Context, host string, answerType int) ([]DNSRecord, error) {
	message, err := c.wireMessage(ctx, host, answerType)
	if err != nil {
		return nil, err
	}
	name, err := ParseName(host)
	if err != nil {
		return nil, err
	}
	authorized, err := AuthorizeAddressAnswers(message, Question{Name: name, Type: uint16(answerType), Class: 1})
	if err != nil {
		return nil, err
	}
	out := make([]DNSRecord, 0, len(authorized))
	for _, answer := range authorized {
		if int(answer.Type) != answerType {
			continue
		}
		if ip := RecordAddress(answer); ip != nil {
			out = append(out, DNSRecord{IP: ip, TTL: int(answer.TTL), TTLPresent: true})
		}
	}
	if len(out) == 0 {
		return nil, errDNSNoData
	}
	return out, nil
}

// LookupDOHType resolves one DNS record family through a DNS-over-HTTPS
// endpoint. RFC 8484 wire format is authoritative; JSON is retained only for
// endpoints that clearly do not implement the wire protocol.
func LookupDOHType(ctx context.Context, serverURL *url.URL, host, dnsType string, answerType int) ([]DNSRecord, error) {
	client, err := NewDOHClient(DOHConfig{ServerURL: serverURL})
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.LookupType(ctx, host, dnsType, answerType)
}

// LookupType performs a wire-first query and permits JSON fallback only after
// the wire endpoint has made a clear protocol incompatibility response.
func (c *DOHClient) LookupType(ctx context.Context, host, dnsType string, answerType int) ([]DNSRecord, error) {
	opCtx, cancel := c.operationContext(ctx)
	defer cancel()
	if records, err := c.lookupWireType(opCtx, host, answerType); err == nil {
		return records, nil
	} else if !errors.Is(err, ErrDOHProtocolIncompatible) {
		return nil, err
	}
	return c.lookupJSONType(opCtx, host, dnsType, answerType)
}

type dohJSONAnswer struct {
	Name string         `json:"name"`
	Type jsontext.Value `json:"type"`
	Data string         `json:"data"`
	TTL  jsontext.Value `json:"TTL"`
}

type dohJSONResponse struct {
	Status jsontext.Value  `json:"Status"`
	Answer []dohJSONAnswer `json:"Answer"`
}

// DOHRecord retains the validated DNS record and the original JSON data when
// the endpoint uses the compatibility JSON representation. Data is empty for
// wire responses; callers should use Record in that case.
type DOHRecord struct {
	Record     Record
	Data       string
	TTLPresent bool
}

// LookupInspectionType performs the same wire-first query as LookupType but
// retains all validated record types for DNS inspection.
func (c *DOHClient) LookupInspectionType(ctx context.Context, host, dnsType string, answerType int) ([]DOHRecord, error) {
	opCtx, cancel := c.operationContext(ctx)
	defer cancel()
	message, err := c.wireMessage(opCtx, host, answerType)
	if err == nil {
		name, parseErr := ParseName(host)
		if parseErr != nil {
			return nil, parseErr
		}
		authorized, authErr := AuthorizeAnswers(message, Question{Name: name, Type: uint16(answerType), Class: 1})
		if authErr != nil {
			return nil, authErr
		}
		out := make([]DOHRecord, 0, len(authorized))
		for _, record := range authorized {
			record.TTLPresent = true
			out = append(out, DOHRecord{Record: record, TTLPresent: true})
		}
		return out, nil
	}
	if !errors.Is(err, ErrDOHProtocolIncompatible) {
		return nil, err
	}
	return c.lookupJSONRecords(opCtx, host, dnsType, answerType)
}

func (c *DOHClient) lookupJSONType(ctx context.Context, host, dnsType string, answerType int) ([]DNSRecord, error) {
	records, err := c.lookupJSONRecords(ctx, host, dnsType, answerType)
	if err != nil {
		return nil, err
	}
	out := make([]DNSRecord, 0, len(records))
	for _, item := range records {
		if int(item.Record.Type) != answerType {
			continue
		}
		if ip := RecordAddress(item.Record); ip != nil {
			out = append(out, DNSRecord{IP: ip, TTL: int(item.Record.TTL), TTLPresent: item.TTLPresent})
		}
	}
	if len(out) == 0 {
		return nil, errDNSNoData
	}
	return out, nil
}

func (c *DOHClient) lookupJSONRecords(ctx context.Context, host, dnsType string, answerType int) ([]DOHRecord, error) {
	u := *c.serverURL
	q := u.Query()
	q.Set("name", host)
	q.Set("type", dnsType)
	u.RawQuery = q.Encode()

	requestCtx, cancel := c.operationContext(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", core.UserAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, readErr := readDOHExcerpt(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("DoH JSON response code: %d", resp.StatusCode)
		}
		excerpt := core.TerminalSafeText(raw)
		if excerpt == "" {
			return nil, fmt.Errorf("DoH JSON response code: %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("DoH JSON response code: %d: %s", resp.StatusCode, excerpt)
	}

	rawJSON, err := core.ReadAllLimited(resp.Body, core.MaxDOHJSONResponseBytes, "DoH JSON response")
	if err != nil {
		return nil, err
	}
	var res dohJSONResponse
	if err := json.Unmarshal(rawJSON, &res); err != nil {
		return nil, fmt.Errorf("invalid DoH JSON response: %w", err)
	}
	status, err := parseJSONUint(res.Status, 16, "Status")
	if err != nil {
		return nil, err
	}
	qname, err := ParseName(host)
	if err != nil {
		return nil, err
	}
	question := Question{Name: qname, Type: uint16(answerType), Class: 1}
	message := &Message{Answers: make([]Record, 0, len(res.Answer))}
	parsed := make([]DOHRecord, 0, len(res.Answer))
	age := parseAge(resp.Header.Get("Age"))
	for index, answer := range res.Answer {
		// The JSON representation must carry an owner for every answer. Do
		// not infer the queried name: an omitted owner would let a malformed
		// or spoofed answer become authorized by accident.
		if answer.Name == "" {
			return nil, fmt.Errorf("invalid DoH JSON answer %d owner: name is missing", index)
		}
		owner, err := ParseName(answer.Name)
		if err != nil {
			return nil, fmt.Errorf("invalid DoH JSON answer %d owner: %w", index, err)
		}
		typ, err := parseJSONUint(answer.Type, 16, fmt.Sprintf("Answer[%d].type", index))
		if err != nil {
			return nil, err
		}
		ttl, ttlPresent, err := parseJSONTTL(answer.TTL, index)
		if err != nil {
			return nil, err
		}
		if ttlPresent {
			ttl = subtractAge(ttl, age)
		}
		record := Record{Owner: owner, Type: uint16(typ), Class: 1, TTL: ttl, TTLPresent: ttlPresent}
		data := answer.Data
		raw, generic, genericErr := parseJSONGenericRDATA(answer.Data, uint16(typ))
		if genericErr != nil {
			return nil, fmt.Errorf("invalid DoH JSON RDATA in answer %d: %w", index, genericErr)
		}
		if strings.HasPrefix(strings.TrimSpace(answer.Data), `\#`) && !generic {
			return nil, fmt.Errorf("invalid DoH JSON generic RDATA in answer %d", index)
		}
		if generic {
			record.RData = raw
		}
		switch uint16(typ) {
		case dnsTypeA, dnsTypeAAAA:
			if generic {
				break
			}
			ip := net.ParseIP(answer.Data)
			if ip == nil || (typ == dnsTypeA && ip.To4() == nil) || (typ == dnsTypeAAAA && (ip.To16() == nil || ip.To4() != nil)) {
				return nil, fmt.Errorf("invalid DoH JSON address in answer %d", index)
			}
			if typ == dnsTypeA {
				record.RData = append([]byte(nil), ip.To4()...)
			} else {
				record.RData = append([]byte(nil), ip.To16()...)
			}
		case dnsTypeCNAME:
			var target Name
			var parseErr error
			if generic {
				target, _, parseErr = decodeName(raw, 0)
				if parseErr == nil {
					_, next, nextErr := decodeName(raw, 0)
					if nextErr != nil || next != len(raw) {
						parseErr = errors.New("CNAME generic RDATA has trailing bytes")
					}
				}
			} else {
				target, parseErr = ParseName(answer.Data)
			}
			if parseErr != nil {
				return nil, fmt.Errorf("invalid DoH JSON CNAME in answer %d: %w", index, parseErr)
			}
			record.Target = &target
			record.RData, _ = target.Wire()
		case dnsTypeSVCB, dnsTypeHTTPS:
			var parsed SVCBRecord
			if generic {
				parsed, err = ParseSVCBRData(raw)
			} else {
				parsed, raw, err = parseJSONSVCBPresentation(answer.Data)
			}
			if err != nil {
				return nil, fmt.Errorf("invalid DoH JSON SVCB/HTTPS in answer %d: %w", index, err)
			}
			record.RData = raw
			record.Priority = parsed.Priority
			target := parsed.Target
			record.Target = &target
			record.Params = cloneSVCBParams(parsed.Params)
		default:
			// The JSON data is retained for inspection. Its numeric type and
			// owner were validated above even when this resolver is not using it
			// to return an address.
		}
		message.Answers = append(message.Answers, record)
		parsed = append(parsed, DOHRecord{Record: record, Data: data, TTLPresent: ttlPresent})
	}
	if status != 0 || len(res.Answer) == 0 {
		if status == 0 {
			return nil, errDNSNoData
		}
		// Preserve the actual DNS response code. Only NXDOMAIN is a
		// negative name answer; SERVFAIL, REFUSED, and other server errors
		// must not be mistaken for a safe downgrade.
		name := rcodeName(int(status))
		if name == "" {
			name = RCodeName(uint16(status))
		}
		if status == 3 {
			return nil, fmt.Errorf("no such host: %s", name)
		}
		return nil, fmt.Errorf("DoH JSON response: %s", name)
	}
	answers, err := AuthorizeAnswers(message, question)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(answers))
	for _, answer := range answers {
		allowed[nameKey(answer.Owner)] = struct{}{}
	}
	out := make([]DOHRecord, 0, len(parsed))
	for _, item := range parsed {
		if _, ok := allowed[nameKey(item.Record.Owner)]; ok {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return nil, errDNSNoData
	}
	return out, nil
}

func parseJSONGenericRDATA(value string, typ uint16) ([]byte, bool, error) {
	fields := strings.Fields(value)
	if len(fields) < 3 || fields[0] != `\#` {
		return nil, false, nil
	}
	length, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return nil, true, fmt.Errorf("invalid generic RDATA length")
	}
	raw, err := hex.DecodeString(strings.Join(fields[2:], ""))
	if err != nil || uint64(len(raw)) != length {
		return nil, true, errors.New("generic RDATA length does not match data")
	}
	if err := ValidateRData(typ, raw); err != nil {
		return nil, true, err
	}
	return raw, true, nil
}

func parseJSONUint(raw jsontext.Value, bits int, field string) (uint64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, fmt.Errorf("DoH JSON %s is missing", field)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, bits)
	if err != nil {
		// strconv.NumError includes the input. Do not echo an attacker-sized
		// JSON value into a terminal diagnostic.
		return 0, fmt.Errorf("invalid DoH JSON %s", field)
	}
	return value, nil
}

func parseJSONTTL(raw jsontext.Value, index int) (uint32, bool, error) {
	if len(raw) == 0 {
		return 0, false, nil
	}
	if string(raw) == "null" {
		return 0, false, fmt.Errorf("invalid DoH JSON TTL in answer %d", index)
	}
	value, err := parseJSONUint(raw, 32, fmt.Sprintf("Answer[%d].TTL", index))
	if err != nil {
		return 0, false, err
	}
	return uint32(value), true, nil
}

func parseAge(value string) uint64 {
	if value == "" {
		return 0
	}
	// Age is a single non-negative delta-seconds value. Treat an invalid
	// value as absent, but saturate overflow so it cannot preserve stale TTLs.
	value = strings.TrimSpace(strings.Split(value, ",")[0])
	age, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		if strings.Trim(value, "0123456789") == "" {
			return ^uint64(0)
		}
		return 0
	}
	return age
}

func subtractAge(ttl uint32, age uint64) uint32 {
	if age >= uint64(ttl) {
		return 0
	}
	return ttl - uint32(age)
}

func adjustMessageTTLs(message *Message, age uint64) {
	if age == 0 {
		return
	}
	for _, sections := range []*[]Record{&message.Answers, &message.Authorities, &message.Additionals} {
		for i := range *sections {
			if (*sections)[i].Type != dnsTypeOPT {
				(*sections)[i].TTL = subtractAge((*sections)[i].TTL, age)
			}
		}
	}
}

func readDOHExcerpt(body io.Reader) (string, error) {
	const maxExcerpt = 16 << 10
	raw, err := io.ReadAll(io.LimitReader(body, maxExcerpt+1))
	if len(raw) > maxExcerpt {
		raw = raw[:maxExcerpt]
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}
