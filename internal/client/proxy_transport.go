package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryanfowler/fetch/internal/resolver"
	"golang.org/x/net/idna"
)

// httpsProxyAsHTTP makes net/http use its ordinary HTTP proxy path. The
// connection returned by newHTTPSProxyDialer is already encrypted to the
// proxy, so net/http must not perform a second TLS handshake before CONNECT.
func httpsProxyAsHTTP(proxy *url.URL) *url.URL {
	copy := *proxy
	copy.Scheme = "http"
	if proxy.Port() == "" {
		// Changing the scheme changes net/http's default port. Preserve the
		// HTTPS proxy's 443 endpoint when presenting it as an HTTP CONNECT
		// proxy to the standard transport.
		copy.Host = net.JoinHostPort(proxy.Hostname(), "443")
	}
	return &copy
}

// newHTTPSProxyDialer establishes the TLS connection to an HTTPS proxy. The
// proxy TLS configuration is deliberately independent from the origin TLS
// configuration: --insecure and origin CA files must not weaken this hop.
func newHTTPSProxyDialer(base func(context.Context, string, string) (net.Conn, error), proxy *url.URL, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	proxyTLS := proxyTLSConfig(proxy)
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		connectCtx, cancel := connectContext(ctx, timeout, "HTTPS proxy connect")
		defer cancel()
		address := canonicalProxyAddress(proxy)
		conn, err := base(connectCtx, network, address)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, proxyTLS.Clone())
		if err := tlsConn.HandshakeContext(connectCtx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("HTTPS proxy TLS handshake: %w", err)
		}
		return newConnectDeadlineConn(tlsConn, connectCtx), nil
	}
}

func proxyTLSConfig(proxy *url.URL) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: proxy.Hostname(),
	}
	// Keep this explicit rather than reusing the origin config. SystemCertPool
	// is nil-safe on platforms where it is unavailable.
	if roots, err := x509.SystemCertPool(); err == nil {
		cfg.RootCAs = roots
	}
	return cfg
}

func canonicalProxyAddress(proxy *url.URL) string {
	port := proxy.Port()
	if port == "" {
		switch strings.ToLower(proxy.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			port = "1080"
		}
	}
	return net.JoinHostPort(proxy.Hostname(), port)
}

// newSOCKS5Dialer implements both SOCKS5 modes behind the same dial function.
// socks5 resolves the destination with the configured resolver and sends an IP
// address. socks5h sends the hostname and performs no destination lookup.
func newSOCKS5Dialer(base func(context.Context, string, string) (net.Conn, error), res *resolver.Resolver, proxy *url.URL, localResolve bool, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, fmt.Errorf("SOCKS5 proxy does not support network %q", network)
		}
		connectCtx, cancel := connectContext(ctx, timeout, "SOCKS5 proxy connect")
		defer cancel()
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("SOCKS5 destination %q: %w", address, err)
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("SOCKS5 destination has invalid port %q", portText)
		}

		if localResolve {
			if res == nil {
				return nil, errors.New("SOCKS5 local resolution is unavailable")
			}
			// Use the same resolver-aware race coordinator as direct HTTP
			// connections. The attempt callback owns the SOCKS protocol, while
			// DNS, family preference, cancellation, and loser cleanup remain in
			// one place.
			dialer := NewResolverDialer(res, timeout)
			result, dialErr := dialer.Dial(connectCtx, DialRequest{
				Network: network,
				Host:    host,
				Port:    portText,
				Mode:    DialSOCKS5,
				Attempt: func(attemptCtx context.Context, _ string, ip net.IPAddr) (net.Conn, error) {
					return dialSOCKSConnection(attemptCtx, base, proxy, ipSOCKSDestination(ip.IP, uint16(port)), 0)
				},
			})
			if dialErr != nil {
				return nil, fmt.Errorf("SOCKS5 local lookup %s: %w", host, dialErr)
			}
			return result.Conn, nil
		}

		var destination socksDestination
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			destination = ipSOCKSDestination(ip, uint16(port))
		} else {
			destination, err = hostnameSOCKSDestination(host, uint16(port))
			if err != nil {
				return nil, err
			}
		}
		return dialSOCKSConnection(connectCtx, base, proxy, destination, 0)
	}
}

func dialSOCKSConnection(ctx context.Context, base func(context.Context, string, string) (net.Conn, error), proxy *url.URL, destination socksDestination, timeout time.Duration) (net.Conn, error) {
	connectCtx, cancel := connectContext(ctx, timeout, "SOCKS5 proxy connect")
	defer cancel()
	proxyConn, err := base(connectCtx, "tcp", canonicalProxyAddress(proxy))
	if err != nil {
		return nil, err
	}
	stop := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-connectCtx.Done():
			_ = proxyConn.Close()
		case <-stop:
		}
	}()
	finish := func() {
		close(stop)
		<-exited
	}
	defer finish()

	if deadline, ok := connectCtx.Deadline(); ok {
		_ = proxyConn.SetDeadline(deadline)
	}
	if err := socksGreeting(proxyConn, proxy.User); err != nil {
		_ = proxyConn.Close()
		return nil, err
	}
	if err := socksConnect(proxyConn, destination); err != nil {
		_ = proxyConn.Close()
		return nil, err
	}
	// net/http performs origin TLS after DialContext returns. Retain the
	// establishment deadline until its first application write clears it.
	return newConnectDeadlineConn(proxyConn, connectCtx), nil
}

type socksDestination struct {
	atyp byte
	addr []byte
	port uint16
}

func ipSOCKSDestination(ip net.IP, port uint16) socksDestination {
	if v4 := ip.To4(); v4 != nil {
		return socksDestination{atyp: 1, addr: append([]byte(nil), v4...), port: port}
	}
	return socksDestination{atyp: 4, addr: append([]byte(nil), ip.To16()...), port: port}
}

func hostnameSOCKSDestination(host string, port uint16) (socksDestination, error) {
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(host, "."))
	if err != nil || ascii == "" || len(ascii) > 255 {
		return socksDestination{}, fmt.Errorf("invalid SOCKS5 destination hostname %q", host)
	}
	return socksDestination{atyp: 3, addr: []byte(ascii), port: port}, nil
}

func socksGreeting(conn net.Conn, user *url.Userinfo) error {
	methods := []byte{0x00}
	var username, password string
	if user != nil {
		username = user.Username()
		password, _ = user.Password()
		if len(username) > 255 || len(password) > 255 {
			return errors.New("SOCKS5 proxy credentials are too long")
		}
		methods = append(methods, 0x02)
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if err := writeFull(conn, greeting); err != nil {
		return fmt.Errorf("SOCKS5 greeting: %w", err)
	}
	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return fmt.Errorf("SOCKS5 greeting response: %w", err)
	}
	if response[0] != 0x05 {
		return errors.New("SOCKS5 proxy returned an invalid protocol version")
	}
	switch response[1] {
	case 0x00:
		return nil
	case 0x02:
		if user == nil {
			return errors.New("SOCKS5 proxy requires authentication")
		}
		payload := []byte{0x01, byte(len(username))}
		payload = append(payload, username...)
		payload = append(payload, byte(len(password)))
		payload = append(payload, password...)
		if err := writeFull(conn, payload); err != nil {
			return fmt.Errorf("SOCKS5 authentication: %w", err)
		}
		if _, err := io.ReadFull(conn, response[:]); err != nil {
			return fmt.Errorf("SOCKS5 authentication response: %w", err)
		}
		if response[1] != 0x00 {
			return errors.New("SOCKS5 proxy authentication failed")
		}
		return nil
	default:
		return fmt.Errorf("SOCKS5 proxy selected unsupported authentication method 0x%02x", response[1])
	}
}

func socksConnect(conn net.Conn, destination socksDestination) error {
	if len(destination.addr) == 0 || (destination.atyp == 1 && len(destination.addr) != 4) || (destination.atyp == 4 && len(destination.addr) != 16) || (destination.atyp == 3 && len(destination.addr) > 255) {
		return errors.New("invalid SOCKS5 destination address")
	}
	request := []byte{0x05, 0x01, 0x00, destination.atyp, byte(len(destination.addr))}
	if destination.atyp == 1 || destination.atyp == 4 {
		request = request[:4]
	}
	request = append(request, destination.addr...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], destination.port)
	request = append(request, port[:]...)
	if err := writeFull(conn, request); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT: %w", err)
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT response: %w", err)
	}
	if header[0] != 0x05 {
		return errors.New("SOCKS5 CONNECT returned an invalid protocol version")
	}
	if header[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT failed with code 0x%02x", header[1])
	}
	var length int
	switch header[3] {
	case 0x01:
		length = 4
	case 0x04:
		length = 16
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return fmt.Errorf("SOCKS5 CONNECT bound address: %w", err)
		}
		length = int(n[0])
	default:
		return errors.New("SOCKS5 CONNECT returned an invalid address type")
	}
	bound := make([]byte, length+2)
	if _, err := io.ReadFull(conn, bound); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT bound address: %w", err)
	}
	return nil
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// proxyTransportState is kept small and only records HTTPS proxy endpoints
// selected from the environment. Explicit proxies are configured directly in
// NewClient. This lets the standard http.Transport continue to be exposed to
// existing callers while preserving HTTPS-proxy TLS separation.
type proxyTransportState struct {
	mu    sync.RWMutex
	https map[string]*url.URL
	socks map[string]*url.URL
}

func (s *proxyTransportState) clearHTTPS() {
	s.mu.Lock()
	s.https = nil
	s.mu.Unlock()
}

func (s *proxyTransportState) remember(proxy *url.URL) {
	if proxy == nil || !strings.EqualFold(proxy.Scheme, "https") {
		return
	}
	s.mu.Lock()
	if s.https == nil {
		s.https = make(map[string]*url.URL)
	}
	s.https[canonicalProxyAddress(proxy)] = proxy
	s.mu.Unlock()
}

func (s *proxyTransportState) forgetTarget(target *url.URL) {
	if target == nil {
		return
	}
	s.mu.Lock()
	delete(s.socks, canonicalTargetAddress(target))
	s.mu.Unlock()
}

func (s *proxyTransportState) rememberSocks(target *url.URL, proxy *url.URL) {
	if target == nil || proxy == nil {
		return
	}
	s.mu.Lock()
	if s.socks == nil {
		s.socks = make(map[string]*url.URL)
	}
	s.socks[canonicalTargetAddress(target)] = proxy
	s.mu.Unlock()
}

func (s *proxyTransportState) lookup(address string) (*url.URL, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if proxy := s.socks[address]; proxy != nil {
		return proxy, true
	}
	return s.https[address], false
}

func canonicalTargetAddress(target *url.URL) string {
	port := target.Port()
	if port == "" {
		switch strings.ToLower(target.Scheme) {
		case "http", "ws":
			port = "80"
		default:
			port = "443"
		}
	}
	return net.JoinHostPort(target.Hostname(), port)
}
