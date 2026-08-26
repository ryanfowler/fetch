package resolver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

// Config controls hostname resolution. Endpoint is the validated resolver
// configuration used by production callers. Server is retained for callers
// that construct resolver test fixtures directly.
type Config struct {
	Endpoint *Endpoint
	Server   *url.URL
	Resolve  []ResolveEntry

	// SystemLookupIPAddr replaces the platform resolver in deterministic tests.
	// Production callers leave it nil so net.Resolver remains authoritative for
	// ordinary system A/AAAA lookups.
	SystemLookupIPAddr func(context.Context, string) ([]net.IPAddr, error)

	// The stream hooks are used by DNS-over-TCP and DNS-over-TLS. They keep
	// resolver endpoint bootstrap and dialing injectable without coupling this
	// package to the application client.
	DialContext DialContextFunc
	Bootstrap   BootstrapFunc
	// RoundTripper is used only by DoH. It lets the application inject its
	// resolver-aware HTTP transport without duplicating DoH logic.
	RoundTripper http.RoundTripper
	// Proxy is applied to DoH endpoint requests. The endpoint bootstrap still
	// uses the platform resolver because resolving a custom resolver through
	// itself would recurse.
	Proxy func(*http.Request) (*url.URL, error)
	// SystemPolicy supplies OS resolver-file policy for HTTPS/SVCB discovery
	// when no custom endpoint is configured. A nil value uses the platform
	// resolv.conf path lazily.
	SystemPolicy *SystemResolverPolicy
	TLSConfig    *tls.Config
	CACerts      []*x509.Certificate
	ClientCert   *tls.Certificate
	Insecure     bool
	TLSMin       uint16
	TLSMax       uint16
}

// Resolver resolves names and dials addresses using the configured DNS backend.
type Resolver struct {
	endpoint *Endpoint
	err      error

	dialContext  DialContextFunc
	bootstrap    BootstrapFunc
	roundTripper http.RoundTripper
	proxy        func(*http.Request) (*url.URL, error)
	systemPolicy *SystemResolverPolicy
	dohClient    *DOHClient
	tlsConfig    *tls.Config
	caCerts      []*x509.Certificate
	clientCert   *tls.Certificate
	insecure     bool
	tlsMin       uint16
	tlsMax       uint16
	systemLookup func(context.Context, string) ([]net.IPAddr, error)
	resolve      []ResolveEntry
}

// ResolvedEndpoint contains a parsed host:port address and its resolved IP
// addresses.
type ResolvedEndpoint struct {
	Host  string
	Port  string
	Addrs []net.IPAddr
}

// New returns a resolver for the provided config. Endpoint validation normally
// happens while CLI/config values are parsed. Server supports existing internal
// test fixtures and is converted once here for compatibility.
func New(cfg Config) *Resolver {
	endpoint := cfg.Endpoint
	var err error
	if endpoint == nil && cfg.Server != nil {
		endpoint, err = endpointFromURL(cfg.Server)
	}
	if err == nil {
		err = core.ValidateTLSVersions(cfg.TLSMin, cfg.TLSMax)
	}
	if err == nil && cfg.TLSConfig != nil {
		err = core.ValidateTLSVersions(cfg.TLSConfig.MinVersion, cfg.TLSConfig.MaxVersion)
	}
	systemLookup := cfg.SystemLookupIPAddr
	if systemLookup == nil {
		systemLookup = net.DefaultResolver.LookupIPAddr
	}
	r := &Resolver{
		endpoint:     endpoint,
		err:          err,
		dialContext:  cfg.DialContext,
		bootstrap:    cfg.Bootstrap,
		roundTripper: cfg.RoundTripper,
		proxy:        cfg.Proxy,
		systemPolicy: cfg.SystemPolicy,
		tlsConfig:    cfg.TLSConfig,
		caCerts:      cfg.CACerts,
		clientCert:   cfg.ClientCert,
		insecure:     cfg.Insecure,
		tlsMin:       cfg.TLSMin,
		tlsMax:       cfg.TLSMax,
		systemLookup: systemLookup,
		resolve:      cloneResolveEntries(cfg.Resolve),
	}
	if r.err == nil && endpoint != nil && endpoint.Transport == TransportHTTPS {
		r.dohClient, r.err = NewDOHClient(DOHConfig{
			Endpoint:     endpoint,
			RoundTripper: cfg.RoundTripper,
			Proxy:        cfg.Proxy,
			DialContext:  cfg.DialContext,
			Bootstrap:    cfg.Bootstrap,
			Resolve:      cfg.Resolve,
			TLSConfig:    cfg.TLSConfig,
			CACerts:      cfg.CACerts,
			ClientCert:   cfg.ClientCert,
			Insecure:     cfg.Insecure,
			TLSMin:       cfg.TLSMin,
			TLSMax:       cfg.TLSMax,
		})
	}
	return r
}

// Provenance identifies the resolver policy that supplied addresses. It is
// intentionally display-oriented and contains no credentials.
func (r *Resolver) Provenance() string {
	if r == nil || r.endpoint == nil {
		return "system"
	}
	if r.endpoint.Display != "" {
		return r.endpoint.Display
	}
	return string(r.endpoint.Transport) + "://" + r.endpoint.ConnectHost
}

// CacheIdentity is a canonical, secret-free identity for persistent caches.
// Provenance is intended for display and deliberately omits fields such as a
// DoH query. Cache identity includes every resolver endpoint field that can
// change the answer source or its verification policy.
func (r *Resolver) CacheIdentity() string {
	if r == nil || r.endpoint == nil {
		return "system"
	}
	ep := r.endpoint
	value := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%t|%s|%d|%d|%t|",
		ep.Transport, ep.ConnectHost, ep.Port, ep.Path, ep.RawPath, ep.RawQuery,
		ep.TLSServerName, ep.VerifyTLS, ep.Security, r.tlsMin, r.tlsMax, r.insecure)
	for _, address := range ep.BootstrapAddrs {
		value += address.String() + ","
	}
	for _, cert := range r.caCerts {
		if cert != nil {
			sum := sha256.Sum256(cert.Raw)
			value += "ca=" + hex.EncodeToString(sum[:]) + ","
		}
	}
	// A client certificate can select a different authenticated DNS view. Keep
	// its public certificate chain in the resolver identity without ever
	// including the private key.
	clientCert := r.clientCert
	if clientCert == nil && r.tlsConfig != nil && len(r.tlsConfig.Certificates) > 0 {
		clientCert = &r.tlsConfig.Certificates[0]
	}
	if clientCert != nil {
		for _, der := range clientCert.Certificate {
			sum := sha256.Sum256(der)
			value += "client-cert=" + hex.EncodeToString(sum[:]) + ","
		}
	}
	sum := sha256.Sum256([]byte(value))
	return string(ep.Transport) + ":" + hex.EncodeToString(sum[:])
}

// NetResolver returns a net.Resolver for system or UDP DNS resolution. DoH,
// DoT, and DoQ resolution cannot be represented as a net.Resolver.
func (r *Resolver) NetResolver() *net.Resolver {
	if r == nil || r.endpoint == nil {
		return net.DefaultResolver
	}
	if r.endpoint.Transport == TransportUDP {
		return udpResolver(r.endpoint.Address())
	}
	return nil
}

// Close releases resources owned by the resolver. It is safe to call more
// than once; externally supplied DoH transports remain the caller's
// responsibility.
func (r *Resolver) Close() error {
	if r == nil || r.dohClient == nil {
		return nil
	}
	return r.dohClient.Close()
}

// LookupIPAddr resolves host to IP addresses using the configured backend.
func (r *Resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}

	if r != nil && r.err != nil {
		return nil, r.err
	}

	switch {
	case r == nil || r.endpoint == nil:
		lookup := net.DefaultResolver.LookupIPAddr
		if r != nil && r.systemLookup != nil {
			lookup = r.systemLookup
		}
		return lookupWithTrace(ctx, host, func(ctx context.Context) ([]net.IPAddr, error) {
			addrs, err := lookup(ctx, host)
			return deduplicateAddresses(addrs), err
		})
	case r.endpoint.Transport == TransportUDP:
		return lookupWithTrace(ctx, host, func(ctx context.Context) ([]net.IPAddr, error) {
			return lookupWireIPs(ctx, r.endpoint.Address(), host)
		})
	case r.endpoint.Transport == TransportHTTPS:
		return lookupWithTrace(ctx, host, func(ctx context.Context) ([]net.IPAddr, error) {
			if r.dohClient == nil {
				return nil, errors.New("DoH client is not configured")
			}
			return lookupDOHClient(ctx, r.dohClient, host)
		})
	case r.endpoint.Transport == TransportTCP || r.endpoint.Transport == TransportTLS:
		return lookupWithTrace(ctx, host, func(ctx context.Context) ([]net.IPAddr, error) {
			return lookupStreamIPs(ctx, StreamConfig{
				Endpoint:    r.endpoint,
				DialContext: r.dialContext,
				Bootstrap:   r.bootstrap,
				TLSConfig:   r.tlsConfig,
				CACerts:     r.caCerts,
				ClientCert:  r.clientCert,
				Insecure:    r.insecure,
				TLSMin:      r.tlsMin,
				TLSMax:      r.tlsMax,
			}, host)
		})
	case r.endpoint.Transport == TransportQUIC:
		return lookupWithTrace(ctx, host, func(ctx context.Context) ([]net.IPAddr, error) {
			return lookupDoQIPs(ctx, DoQConfig{
				Endpoint:   r.endpoint,
				Bootstrap:  r.bootstrap,
				TLSConfig:  r.tlsConfig,
				CACerts:    r.caCerts,
				ClientCert: r.clientCert,
				Insecure:   r.insecure,
				TLSMin:     r.tlsMin,
				TLSMax:     r.tlsMax,
			}, host)
		})
	default:
		return nil, fmt.Errorf("resolver transport %s is not implemented", r.endpoint.Transport)
	}
}

// ResolveAddress resolves the host portion of network address.
func (r *Resolver) ResolveAddress(ctx context.Context, network, address string) (ResolvedEndpoint, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return ResolvedEndpoint{}, err
	}
	if endpoint, ok, err := r.ResolveAddressOverride(network, host, port); ok {
		return endpoint, err
	}

	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return ResolvedEndpoint{}, fmt.Errorf("lookup %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return ResolvedEndpoint{}, fmt.Errorf("lookup %s: no addresses found", host)
	}

	return resolvedEndpoint(network, host, port, addrs)
}

// ResolveAddressOverride returns addresses configured for host and port by a
// static resolve entry. The boolean distinguishes an absent entry from an
// entry whose address is unusable for the requested network.
func (r *Resolver) ResolveAddressOverride(network, host, port string) (ResolvedEndpoint, bool, error) {
	if r == nil || len(r.resolve) == 0 {
		return ResolvedEndpoint{}, false, nil
	}
	return resolveAddressOverride(r.resolve, network, host, port)
}

func resolveAddressOverride(entries []ResolveEntry, network, host, port string) (ResolvedEndpoint, bool, error) {
	port = normalizeResolvePort(port)
	var exact, wildcard []net.IPAddr
	for _, entry := range entries {
		if normalizeResolvePort(entry.Port) != port {
			continue
		}
		addr := net.IPAddr{IP: append(net.IP(nil), entry.IP...)}
		if entry.Host == "*" {
			wildcard = append(wildcard, addr)
		} else if strings.EqualFold(strings.TrimSuffix(entry.Host, "."), strings.TrimSuffix(host, ".")) {
			exact = append(exact, addr)
		}
	}
	if len(exact) == 0 && len(wildcard) == 0 {
		return ResolvedEndpoint{}, false, nil
	}
	if len(exact) > 0 {
		endpoint, err := resolvedEndpoint(network, host, port, exact)
		return endpoint, true, err
	}
	endpoint, err := resolvedEndpoint(network, host, port, wildcard)
	return endpoint, true, err
}

func normalizeResolvePort(port string) string {
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return port
	}
	return strconv.FormatUint(portNumber, 10)
}

func resolvedEndpoint(network, host, port string, addrs []net.IPAddr) (ResolvedEndpoint, error) {
	addrs = deduplicateAddresses(addrs)
	// A family-specific network must not waste attempts on addresses that the
	// platform dialer will reject. For dual-stack networks, retain the
	// resolver-preferred family and interleave the other family below.
	switch strings.ToLower(network) {
	case "tcp4", "udp4":
		filtered := make([]net.IPAddr, 0, len(addrs))
		for _, addr := range addrs {
			if addr.IP.To4() != nil {
				filtered = append(filtered, addr)
			}
		}
		addrs = filtered
	case "tcp6", "udp6":
		filtered := make([]net.IPAddr, 0, len(addrs))
		for _, addr := range addrs {
			if addr.IP.To4() == nil && addr.IP.To16() != nil {
				filtered = append(filtered, addr)
			}
		}
		addrs = filtered
	}
	if len(addrs) == 0 {
		return ResolvedEndpoint{}, fmt.Errorf("lookup %s: no addresses for network %s", host, network)
	}

	// Keep the resolver-preferred family first while interleaving later
	// candidates for Happy Eyeballs. Cap the shared dial surface before any
	// caller can start sockets from a large but valid RRset.
	addrs = interleaveAddressFamilies(addrs)
	if len(addrs) > maxDialCandidates {
		addrs = addrs[:maxDialCandidates]
	}
	return ResolvedEndpoint{Host: host, Port: port, Addrs: addrs}, nil
}

func cloneResolveEntries(values []ResolveEntry) []ResolveEntry {
	out := make([]ResolveEntry, len(values))
	for i, value := range values {
		out[i] = value
		out[i].IP = append(net.IP(nil), value.IP...)
	}
	return out
}

// DialContext resolves address and dials each returned IP until one succeeds.
// DialContext resolves address and races its candidates with the shared
// Happy Eyeballs policy. The first address retains the resolver's preferred
// family; later candidates are interleaved by ResolveAddress.
func (r *Resolver) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// A DoH endpoint cannot resolve its own hostname through the DoH client.
	// Bootstrap this one first hop with its explicit addresses or the platform
	// resolver, while all application destinations continue to use the selected
	// resolver normally.
	if r != nil && r.endpoint != nil && r.endpoint.Transport == TransportHTTPS {
		if host, port, splitErr := net.SplitHostPort(address); splitErr == nil && strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(r.endpoint.ConnectHost, ".")) {
			addrs := make([]net.IPAddr, 0, len(r.endpoint.BootstrapAddrs))
			for _, ip := range r.endpoint.BootstrapAddrs {
				addrs = append(addrs, net.IPAddr{IP: append(net.IP(nil), ip...)})
			}
			if override, ok, overrideErr := r.ResolveAddressOverride(network, host, port); ok {
				if overrideErr != nil {
					return nil, overrideErr
				}
				addrs = override.Addrs
				port = override.Port
			}
			if len(addrs) == 0 {
				var lookupErr error
				addrs, lookupErr = net.DefaultResolver.LookupIPAddr(ctx, host)
				if lookupErr != nil {
					return nil, lookupErr
				}
			}
			return RaceCandidates(ctx, addrs, func(ctx context.Context, addr net.IPAddr) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, network, core.JoinIPHostPort(addr, port))
			}, func(conn net.Conn) {
				if conn != nil {
					_ = conn.Close()
				}
			})
		}
	}
	endpoint, err := r.ResolveAddress(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return RaceCandidates(ctx, endpoint.Addrs, func(ctx context.Context, addr net.IPAddr) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, core.JoinIPHostPort(addr, endpoint.Port))
	}, func(conn net.Conn) {
		if conn != nil {
			_ = conn.Close()
		}
	})
}

func endpointFromURL(u *url.URL) (*Endpoint, error) {
	if u == nil {
		return nil, nil
	}
	if u.Scheme == "" {
		value := u.Host
		if value == "" {
			return nil, endpointError(u.String(), "host is empty")
		}
		host, port, err := parseHostPort(value, 53)
		if err != nil {
			return nil, endpointError(u.String(), err.Error())
		}
		return newEndpoint(TransportUDP, host, port, "", "", "", false), nil
	}
	return parseEndpoint(u.String(), strings.EqualFold(u.Scheme, "http"))
}

func lookupWithTrace(ctx context.Context, host string, lookup func(context.Context) ([]net.IPAddr, error)) ([]net.IPAddr, error) {
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.DNSStart != nil {
		trace.DNSStart(httptrace.DNSStartInfo{Host: host})
	}

	addrs, err := lookup(ctx)

	if trace != nil && trace.DNSDone != nil {
		info := httptrace.DNSDoneInfo{Err: err}
		if err == nil {
			info.Addrs = addrs
		}
		trace.DNSDone(info)
	}

	return addrs, err
}
