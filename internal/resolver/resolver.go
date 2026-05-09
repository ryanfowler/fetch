package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http/httptrace"
	"net/url"
)

// Config controls hostname resolution. A nil Server uses the system resolver,
// a URL with an empty scheme uses UDP DNS, and http/https URLs use DoH.
type Config struct {
	Server *url.URL
}

// Resolver resolves names and dials addresses using the configured DNS backend.
type Resolver struct {
	server *url.URL
}

// Endpoint contains a parsed host:port address and its resolved IP addresses.
type Endpoint struct {
	Host  string
	Port  string
	Addrs []net.IPAddr
}

// New returns a resolver for the provided config.
func New(cfg Config) *Resolver {
	return &Resolver{server: cfg.Server}
}

// NetResolver returns a net.Resolver for system or UDP DNS resolution. DoH
// resolution cannot be represented as a net.Resolver, so nil is returned.
func (r *Resolver) NetResolver() *net.Resolver {
	if r == nil || r.server == nil {
		return net.DefaultResolver
	}
	if r.server.Scheme == "" {
		return udpResolver(r.server.Host)
	}
	return nil
}

// LookupIPAddr resolves host to IP addresses using the configured backend.
func (r *Resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}

	switch {
	case r == nil || r.server == nil:
		return lookupWithTrace(ctx, host, func(ctx context.Context) ([]net.IPAddr, error) {
			return net.DefaultResolver.LookupIPAddr(ctx, host)
		})
	case r.server.Scheme == "":
		res := udpResolver(r.server.Host)
		return lookupWithTrace(ctx, host, func(ctx context.Context) ([]net.IPAddr, error) {
			return res.LookupIPAddr(ctx, host)
		})
	default:
		return lookupWithTrace(ctx, host, func(ctx context.Context) ([]net.IPAddr, error) {
			return lookupDOH(ctx, r.server, host)
		})
	}
}

// ResolveAddress resolves the host portion of network address.
func (r *Resolver) ResolveAddress(ctx context.Context, network, address string) (Endpoint, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return Endpoint{}, err
	}

	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return Endpoint{}, fmt.Errorf("lookup %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return Endpoint{}, fmt.Errorf("lookup %s: no addresses found", host)
	}

	return Endpoint{Host: host, Port: port, Addrs: addrs}, nil
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
