package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
)

const maxHTTPSAliasDepth = 8

// ErrHTTPSRecordsUnavailable means that the selected resolver cannot query
// HTTPS records. Callers may use ordinary ALPN negotiation in this case.
var ErrHTTPSRecordsUnavailable = errors.New("HTTPS record discovery is unavailable")

// ErrDNSNoData is returned when an authenticated DNS response contains no
// records of the requested type.
var ErrDNSNoData = errDNSNoData

// HTTPSRecordLookup returns the validated HTTPS records for name. The lookup
// must authorize owners and validate the complete RRset before returning.
type HTTPSRecordLookup func(context.Context, string) ([]Record, error)

// AddressLookup resolves the A and AAAA records for name.
type AddressLookup func(context.Context, string) ([]net.IPAddr, error)

// DiscoveryFailureKind describes whether HTTPS discovery may safely be
// skipped. Authenticated protocol failures must not be silently downgraded.
type DiscoveryFailureKind uint8

const (
	DiscoveryFailureUnknown DiscoveryFailureKind = iota
	DiscoveryFailureNODATA
	DiscoveryFailureNXDOMAIN
	DiscoveryFailureUnauthenticated
	DiscoveryFailureAuthenticated
)

// DiscoveryError keeps downgrade policy separate from error text. The wrapped
// error remains available to callers with errors.Is/errors.As.
type DiscoveryError struct {
	Kind DiscoveryFailureKind
	Err  error
}

func (e *DiscoveryError) Error() string {
	if e == nil || e.Err == nil {
		return "HTTPS discovery failed"
	}
	return "HTTPS discovery: " + e.Err.Error()
}

func (e *DiscoveryError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// DiscoveryFailure reports the policy classification of err.
func DiscoveryFailure(err error) DiscoveryFailureKind {
	var discoveryErr *DiscoveryError
	if errors.As(err, &discoveryErr) && discoveryErr != nil {
		return discoveryErr.Kind
	}
	return DiscoveryFailureUnknown
}

// MayDowngrade reports whether ordinary ALPN negotiation is allowed after an
// HTTPS discovery failure. Authenticated NODATA and NXDOMAIN are normal DNS
// outcomes; authenticated transport, parsing, and server failures are not.
func IsAuthenticatedDiscoveryFailure(err error) bool {
	return DiscoveryFailure(err) == DiscoveryFailureAuthenticated
}

func MayDowngrade(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	switch DiscoveryFailure(err) {
	case DiscoveryFailureNODATA, DiscoveryFailureNXDOMAIN, DiscoveryFailureUnauthenticated:
		return true
	default:
		return false
	}
}

// ServiceCandidate is an effective HTTPS/SVCB service candidate. OriginName is
// the name used for HTTP authority and TLS SNI. TargetName is the name whose
// service is used for dialing and address resolution.
type ServiceCandidate struct {
	OriginName    Name
	TargetName    Name
	Priority      uint16
	Port          uint16
	ALPN          [][]byte
	NoDefaultALPN bool
	ECH           []byte
	Hints         []net.IPAddr
	Addresses     []net.IPAddr
	TTL           uint32
	TTLPresent    bool
}

// HTTPSDiscovery is the result of following AliasMode and selecting usable
// ServiceMode records. EffectiveTarget is the final target used for service
// discovery, even when no usable ServiceMode record exists.
type HTTPSDiscovery struct {
	Origin            Name
	EffectiveTarget   Name
	Candidates        []ServiceCandidate
	FallbackAddresses []net.IPAddr
	FallbackPort      uint16
	TTL               uint32
	TTLPresent        bool
	Authenticated     bool
	Security          Security
}

// ServiceDiscoveryOptions controls the resolver-independent discovery engine.
// DefaultPort is used when a service record does not advertise port 443.
type ServiceDiscoveryOptions struct {
	DefaultPort   uint16
	MaxAliasDepth int
	RandomInt     func(int) int
	AddressLookup AddressLookup
	// Authenticated marks errors returned by a certificate-verified DNS
	// transport. It controls downgrade policy for parsing and address errors.
	Authenticated bool
}

// ResolveHTTPS follows AliasMode chains and turns ServiceMode records into
// address candidates. It is independent of a particular DNS transport so all
// resolver implementations can share the same policy and tests can use a
// deterministic lookup fixture.
func ResolveHTTPS(ctx context.Context, host string, records HTTPSRecordLookup, addresses AddressLookup, options ServiceDiscoveryOptions) (HTTPSDiscovery, error) {
	origin, err := ParseName(host)
	if err != nil {
		return HTTPSDiscovery{}, err
	}
	if records == nil {
		return HTTPSDiscovery{}, &DiscoveryError{Kind: DiscoveryFailureUnknown, Err: errors.New("HTTPS record lookup is not configured")}
	}
	if options.DefaultPort == 0 {
		options.DefaultPort = 443
	}
	if options.MaxAliasDepth <= 0 {
		options.MaxAliasDepth = maxHTTPSAliasDepth
	}
	if addresses == nil {
		addresses = options.AddressLookup
	}

	result := HTTPSDiscovery{Origin: origin, EffectiveTarget: origin, FallbackPort: options.DefaultPort}
	current := origin
	seen := map[string]struct{}{nameKey(current): {}}

	for depth := 0; ; depth++ {
		if err := contextError(ctx); err != nil {
			return result, err
		}
		answer, err := records(ctx, current.String())
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return result, err
			}
			classified := classifyDiscoveryError(err, options.Authenticated)
			if !current.Equal(origin) && addresses != nil && MayDowngrade(classified) {
				fallback, fallbackErr := resolveServiceAddresses(ctx, current.String(), nil, addresses)
				if fallbackErr == nil {
					result.FallbackAddresses = fallback
				} else if errors.Is(fallbackErr, context.Canceled) || errors.Is(fallbackErr, context.DeadlineExceeded) {
					return result, fallbackErr
				}
			}
			return result, classified
		}
		bindings, err := ParseSVCBRRSet(answer)
		if err != nil {
			return result, classifyDiscoveryError(err, options.Authenticated)
		}

		aliases := make([]SVCBRecord, 0, len(bindings))
		services := make([]SVCBRecord, 0, len(bindings))
		for _, binding := range bindings {
			if binding.IsAliasMode() {
				aliases = append(aliases, binding)
			} else if binding.IsUsable() {
				services = append(services, binding)
			}
		}

		if len(aliases) > 0 {
			if depth >= options.MaxAliasDepth {
				// An incomplete alias chain must not redirect a request to a
				// partially discovered target. Keep the original authority as
				// the safe fallback target.
				result.EffectiveTarget = origin
				return result, nil
			}
			// AliasMode records all have priority zero. Apply the same
			// equal-priority randomization as ServiceMode records before
			// selecting one target.
			aliases = SortSVCBRecords(aliases, options.RandomInt)
			mergeDiscoveryTTL(&result, aliases[0].TTL, aliases[0].TTLPresent)
			target := aliases[0].Target
			// RFC 9460 uses the root target to signal that service is
			// unavailable. It is not an alias to the current owner.
			if target.String() == "." {
				result.EffectiveTarget = origin
				return result, nil
			}
			key := nameKey(target)
			if _, ok := seen[key]; ok {
				result.EffectiveTarget = origin
				return result, nil
			}
			seen[key] = struct{}{}
			current = target
			result.EffectiveTarget = target
			continue
		}

		result.EffectiveTarget = current
		if len(services) == 0 {
			if !current.Equal(origin) && addresses != nil {
				fallback, fallbackErr := resolveServiceAddresses(ctx, current.String(), nil, addresses)
				if fallbackErr != nil {
					return result, classifyDiscoveryError(fallbackErr, options.Authenticated)
				}
				result.FallbackAddresses = fallback
			}
			return result, nil
		}
		services = SortSVCBRecords(services, options.RandomInt)
		result.Candidates = make([]ServiceCandidate, 0, len(services))
		for _, service := range services {
			target := service.Target
			// In ServiceMode, the root target means the owner of this RRset,
			// not the origin name that started AliasMode processing.
			if target.String() == "." {
				target = service.Owner
				if target.String() == "." {
					target = current
				}
			}
			candidateTTL, candidateTTLPresent := service.TTL, service.TTLPresent
			if result.TTLPresent && (!candidateTTLPresent || result.TTL < candidateTTL) {
				candidateTTL, candidateTTLPresent = result.TTL, true
			}
			candidate := ServiceCandidate{
				OriginName:    origin,
				TargetName:    target,
				Priority:      service.Priority,
				Port:          options.DefaultPort,
				ALPN:          cloneALPN(service.ALPN),
				NoDefaultALPN: service.NoDefaultALPN,
				ECH:           append([]byte(nil), service.ECH...),
				TTL:           candidateTTL,
				TTLPresent:    candidateTTLPresent,
			}
			if service.HasPort {
				candidate.Port = service.Port
			}
			candidate.Hints = serviceHints(service)
			candidate.Addresses = append([]net.IPAddr(nil), candidate.Hints...)
			if addresses != nil {
				resolved, resolveErr := resolveServiceAddresses(ctx, candidate.TargetName.String(), candidate.Hints, addresses)
				if resolveErr != nil {
					classified := classifyDiscoveryError(resolveErr, false)
					if errors.Is(resolveErr, context.Canceled) || errors.Is(resolveErr, context.DeadlineExceeded) || len(candidate.Addresses) == 0 || !MayDowngrade(classified) {
						return result, classified
					}
				} else {
					candidate.Addresses = appendAddressLists(candidate.Addresses, resolved)
				}
			}
			mergeDiscoveryTTL(&result, service.TTL, service.TTLPresent)
			result.Candidates = append(result.Candidates, candidate)
		}
		return result, nil
	}
}

func mergeDiscoveryTTL(result *HTTPSDiscovery, ttl uint32, present bool) {
	if result == nil || !present {
		return
	}
	if !result.TTLPresent || ttl < result.TTL {
		result.TTL = ttl
	}
	result.TTLPresent = true
}

func cloneALPN(values [][]byte) [][]byte {
	out := make([][]byte, len(values))
	for i, value := range values {
		out[i] = append([]byte(nil), value...)
	}
	return out
}

func serviceHints(service SVCBRecord) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(service.IPv4Hints)+len(service.IPv6Hints))
	for _, ip := range service.IPv4Hints {
		if ipv4 := ip.To4(); ipv4 != nil {
			out = append(out, net.IPAddr{IP: append(net.IP(nil), ipv4...)})
		}
	}
	for _, ip := range service.IPv6Hints {
		out = append(out, net.IPAddr{IP: append(net.IP(nil), ip...)})
	}
	return deduplicateAddresses(out)
}

// resolveServiceAddresses starts target resolution immediately and returns
// the complete, deduplicated set. Discovery keeps the caller's context so a
// delayed target lookup cannot outlive the shared operation budget.
func resolveServiceAddresses(ctx context.Context, target string, hints []net.IPAddr, lookup AddressLookup) ([]net.IPAddr, error) {
	result := make(chan struct {
		addrs []net.IPAddr
		err   error
	}, 1)
	go func() {
		addrs, err := lookup(ctx, target)
		result <- struct {
			addrs []net.IPAddr
			err   error
		}{deduplicateAddresses(addrs), err}
	}()
	select {
	case got := <-result:
		return got.addrs, got.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func classifyDiscoveryError(err error, authenticated bool) error {
	if err == nil {
		return nil
	}
	var existing *DiscoveryError
	if errors.As(err, &existing) {
		return err
	}
	if errors.Is(err, errDNSNoData) || strings.Contains(strings.ToLower(err.Error()), "nodata") {
		return &DiscoveryError{Kind: DiscoveryFailureNODATA, Err: err}
	}
	if strings.Contains(strings.ToLower(err.Error()), "nxdomain") || strings.Contains(strings.ToLower(err.Error()), "no such host") {
		return &DiscoveryError{Kind: DiscoveryFailureNXDOMAIN, Err: err}
	}
	kind := DiscoveryFailureUnauthenticated
	if authenticated {
		kind = DiscoveryFailureAuthenticated
	}
	return &DiscoveryError{Kind: kind, Err: err}
}

// LookupHTTPSRecords queries and authorizes one HTTPS RRset through the
// configured resolver. It is also useful to H3/ECH callers that need raw
// records without invoking the full candidate builder.
func (r *Resolver) LookupHTTPSRecords(ctx context.Context, host string) ([]Record, error) {
	return r.lookupServiceRecords(ctx, host, dnsTypeHTTPS)
}

// LookupSVCBRecords is the equivalent raw-record operation for SVCB queries.
func (r *Resolver) LookupSVCBRecords(ctx context.Context, host string) ([]Record, error) {
	return r.lookupServiceRecords(ctx, host, dnsTypeSVCB)
}

// DiscoverHTTPS follows the configured resolver's HTTPS AliasMode and returns
// effective service/address candidates for the supplied origin.
func (r *Resolver) DiscoverHTTPS(ctx context.Context, host string, defaultPort uint16, randomInt func(int) int) (HTTPSDiscovery, error) {
	return r.DiscoverService(ctx, host, dnsTypeHTTPS, defaultPort, randomInt)
}

// DiscoverSVCB follows SVCB AliasMode with the same candidate and downgrade
// policy as HTTPS discovery.
func (r *Resolver) DiscoverSVCB(ctx context.Context, host string, defaultPort uint16, randomInt func(int) int) (HTTPSDiscovery, error) {
	return r.DiscoverService(ctx, host, dnsTypeSVCB, defaultPort, randomInt)
}

// DiscoverService follows the selected HTTPS/SVCB record type through the
// configured resolver. The returned OriginName values remain the original
// authority even when a service target is different.
func (r *Resolver) DiscoverService(ctx context.Context, host string, typ uint16, defaultPort uint16, randomInt func(int) int) (HTTPSDiscovery, error) {
	if typ != dnsTypeHTTPS && typ != dnsTypeSVCB {
		return HTTPSDiscovery{}, fmt.Errorf("service discovery does not support DNS type %d", typ)
	}
	if r == nil {
		return HTTPSDiscovery{}, &DiscoveryError{Kind: DiscoveryFailureUnauthenticated, Err: ErrHTTPSRecordsUnavailable}
	}
	authenticated := r.endpoint != nil && r.endpoint.Security == SecurityVerifiedEncrypted && !r.insecure
	security := SecurityPlaintext
	if r.endpoint != nil {
		security = r.endpoint.Security
		if r.insecure && security != SecurityPlaintext {
			security = SecurityUnverifiedEncrypt
		}
	}
	lookup := func(ctx context.Context, name string) ([]Record, error) {
		var values []Record
		var err error
		if typ == dnsTypeHTTPS {
			values, err = r.LookupHTTPSRecords(ctx, name)
		} else {
			values, err = r.LookupSVCBRecords(ctx, name)
		}
		if err != nil {
			return nil, classifyDiscoveryError(err, authenticated)
		}
		return values, nil
	}
	addressLookup := func(ctx context.Context, name string) ([]net.IPAddr, error) {
		values, err := r.LookupIPAddr(ctx, name)
		if err != nil {
			return nil, classifyDiscoveryError(err, authenticated)
		}
		return values, nil
	}
	result, err := ResolveHTTPS(ctx, host, lookup, addressLookup, ServiceDiscoveryOptions{DefaultPort: defaultPort, RandomInt: randomInt, Authenticated: authenticated})
	result.Authenticated = authenticated
	result.Security = security
	return result, err
}

func (r *Resolver) lookupServiceRecords(ctx context.Context, host string, typ uint16) ([]Record, error) {
	if r == nil || r.err != nil {
		if r != nil && r.err != nil {
			return nil, r.err
		}
		return nil, ErrHTTPSRecordsUnavailable
	}
	qname, err := ParseName(host)
	if err != nil {
		return nil, err
	}
	question := Question{Name: qname, Type: typ, Class: 1}
	var message *Message
	switch {
	case r.endpoint == nil:
		policy := r.systemPolicy
		if policy == nil {
			if runtime.GOOS == "windows" {
				return nil, ErrHTTPSRecordsUnavailable
			}
			path := "/etc/resolv.conf"
			loaded, readErr := LoadSystemResolverPolicy(path)
			if readErr != nil {
				return nil, fmt.Errorf("read system resolver policy: %w", readErr)
			}
			policy = &loaded
		}
		return QuerySystemHTTPS(ctx, *policy, host, typ)
	case r.endpoint.Transport == TransportUDP:
		message, _, err = LookupUDPMessage(ctx, r.endpoint.Address(), host, typ)
	case r.endpoint.Transport == TransportTCP || r.endpoint.Transport == TransportTLS:
		message, err = LookupStreamMessage(ctx, StreamConfig{Endpoint: r.endpoint, DialContext: r.dialContext, Bootstrap: r.bootstrap, TLSConfig: r.tlsConfig, CACerts: r.caCerts, ClientCert: r.clientCert, Insecure: r.insecure, TLSMin: r.tlsMin, TLSMax: r.tlsMax}, host, typ)
	case r.endpoint.Transport == TransportQUIC:
		message, err = LookupDoQMessage(ctx, DoQConfig{Endpoint: r.endpoint, Bootstrap: r.bootstrap, TLSConfig: r.tlsConfig, CACerts: r.caCerts, ClientCert: r.clientCert, Insecure: r.insecure, TLSMin: r.tlsMin, TLSMax: r.tlsMax}, host, typ)
	case r.endpoint.Transport == TransportHTTPS:
		if r.dohClient == nil {
			return nil, ErrHTTPSRecordsUnavailable
		}
		records, dohErr := r.dohClient.LookupInspectionType(ctx, host, dnsTypeName(typ), int(typ))
		if dohErr != nil {
			return nil, dohErr
		}
		out := make([]Record, 0, len(records))
		for _, record := range records {
			if record.Record.Type == typ {
				out = append(out, record.Record)
			}
		}
		if len(out) == 0 {
			return nil, errDNSNoData
		}
		return out, nil
	default:
		return nil, fmt.Errorf("resolver transport %s is not implemented", r.endpoint.Transport)
	}
	if err != nil {
		return nil, err
	}
	if message == nil {
		return nil, errors.New("DNS response is empty")
	}
	if message.Header.RCode != 0 {
		if message.Header.RCode == 3 {
			return nil, fmt.Errorf("DNS response: NXDomain")
		}
		return nil, fmt.Errorf("DNS response: %s", RCodeName(message.Header.RCode))
	}
	authorized, err := AuthorizeAnswers(message, question)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(authorized))
	for _, record := range authorized {
		if record.Type == typ {
			out = append(out, record)
		}
	}
	if len(out) == 0 {
		return nil, errDNSNoData
	}
	return out, nil
}

func dnsTypeName(typ uint16) string {
	switch typ {
	case dnsTypeHTTPS:
		return "HTTPS"
	case dnsTypeSVCB:
		return "SVCB"
	default:
		return strconv.Itoa(int(typ))
	}
}
