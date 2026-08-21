package resolver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http/httptrace"
	"net/url"
	"strings"
)

// Config controls hostname resolution. Endpoint is the validated resolver
// configuration used by production callers. Server is retained for callers
// that construct resolver test fixtures directly.
type Config struct {
	Endpoint *Endpoint
	Server   *url.URL

	// The stream hooks are used by DNS-over-TCP and DNS-over-TLS. They keep
	// resolver endpoint bootstrap and dialing injectable without coupling this
	// package to the application client.
	DialContext DialContextFunc
	Bootstrap   BootstrapFunc
	TLSConfig   *tls.Config
	CACerts     []*x509.Certificate
	Insecure    bool
	TLSMin      uint16
	TLSMax      uint16
}

// Resolver resolves names and dials addresses using the configured DNS backend.
type Resolver struct {
	endpoint *Endpoint
	err      error

	dialContext DialContextFunc
	bootstrap   BootstrapFunc
	tlsConfig   *tls.Config
	caCerts     []*x509.Certificate
	insecure    bool
	tlsMin      uint16
	tlsMax      uint16
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
	return &Resolver{
		endpoint:    endpoint,
		err:         err,
		dialContext: cfg.DialContext,
		bootstrap:   cfg.Bootstrap,
		tlsConfig:   cfg.TLSConfig,
		caCerts:     cfg.CACerts,
		insecure:    cfg.Insecure,
		tlsMin:      cfg.TLSMin,
		tlsMax:      cfg.TLSMax,
	}
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
		return lookupWithTrace(ctx, host, func(ctx context.Context) ([]net.IPAddr, error) {
			return net.DefaultResolver.LookupIPAddr(ctx, host)
		})
	case r.endpoint.Transport == TransportUDP:
		return lookupWithTrace(ctx, host, func(ctx context.Context) ([]net.IPAddr, error) {
			return lookupWireIPs(ctx, r.endpoint.Address(), host)
		})
	case r.endpoint.Transport == TransportHTTPS:
		return lookupWithTrace(ctx, host, func(ctx context.Context) ([]net.IPAddr, error) {
			return lookupDOH(ctx, r.endpoint.URL(), host)
		})
	case r.endpoint.Transport == TransportTCP || r.endpoint.Transport == TransportTLS:
		return lookupWithTrace(ctx, host, func(ctx context.Context) ([]net.IPAddr, error) {
			return lookupStreamIPs(ctx, StreamConfig{
				Endpoint:    r.endpoint,
				DialContext: r.dialContext,
				Bootstrap:   r.bootstrap,
				TLSConfig:   r.tlsConfig,
				CACerts:     r.caCerts,
				Insecure:    r.insecure,
				TLSMin:      r.tlsMin,
				TLSMax:      r.tlsMax,
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

	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return ResolvedEndpoint{}, fmt.Errorf("lookup %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return ResolvedEndpoint{}, fmt.Errorf("lookup %s: no addresses found", host)
	}

	return ResolvedEndpoint{Host: host, Port: port, Addrs: addrs}, nil
}

// DialContext resolves address and dials each returned IP until one succeeds.
func (r *Resolver) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	endpoint, err := r.ResolveAddress(ctx, network, address)
	if err != nil {
		return nil, err
	}

	var dialer net.Dialer
	for _, addr := range endpoint.Addrs {
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), endpoint.Port))
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	if err == nil {
		err = errors.New("no addresses found")
	}
	return nil, err
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
