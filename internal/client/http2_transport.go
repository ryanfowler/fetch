package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"
)

// getHTTP2Transport returns a standard-library transport restricted to TLS
// HTTP/2. Go 1.27 exposes HTTP/2 and h2c configuration directly on
// http.Transport, so the legacy x/net/http2.Transport is no longer needed.
func getHTTP2Transport(baseDial func(context.Context, string, string) (net.Conn, error), res *resolver.Resolver, explicitProxy *url.URL, tlsConfig *tls.Config, connectTimeout time.Duration, echMode core.ECHMode) http.RoundTripper {
	rt := newHTTP2Transport(baseDial, res, explicitProxy, tlsConfig, connectTimeout, false)
	rt.Protocols.SetHTTP2(true)

	if echMode != core.ECHUnknown && echMode != core.ECHOff && explicitProxy == nil {
		// net/http otherwise creates the TLS config before the resolver can
		// supply the origin's ECH configuration. Proxy-specific ECH wiring is
		// deliberately excluded by the client's ECH policy.
		rt.DialTLSContext = newECHHTTPDialTLS(baseDial, res, tlsConfig, echMode, connectTimeout, core.HTTP2)
	}

	return restrictHTTP2Scheme(wrapHTTP2ProxyTransport(rt, explicitProxy), "https")
}

// getH2CTransport returns a standard-library transport restricted to cleartext
// HTTP/2. The Protocols API is the replacement for http2.Transport.AllowHTTP.
func getH2CTransport(baseDial func(context.Context, string, string) (net.Conn, error), res *resolver.Resolver, explicitProxy *url.URL, connectTimeout time.Duration) http.RoundTripper {
	rt := newHTTP2Transport(baseDial, res, explicitProxy, nil, connectTimeout, true)
	rt.Protocols.SetUnencryptedHTTP2(true)
	return restrictHTTP2Scheme(wrapHTTP2ProxyTransport(rt, explicitProxy), "http")
}

func newHTTP2Transport(baseDial func(context.Context, string, string) (net.Conn, error), res *resolver.Resolver, explicitProxy *url.URL, tlsConfig *tls.Config, connectTimeout time.Duration, h2c bool) *http.Transport {
	rt := &http.Transport{
		DisableCompression: true,
		Protocols:          &http.Protocols{},
	}
	if tlsConfig != nil {
		rt.TLSClientConfig = tlsConfig.Clone()
	}

	proxy := ProxyFunc(explicitProxy)
	transportProxy := func(req *http.Request) (*url.URL, error) {
		selected, ok := selectedProxy(req.Context())
		if !ok {
			var err error
			selected, err = proxy(req)
			if err != nil {
				return nil, err
			}
		}
		if selected == nil {
			return nil, nil
		}
		if h2c {
			// A cleartext HTTP/2 origin cannot use net/http's ordinary
			// absolute-form HTTP proxy path. The dialer establishes a CONNECT
			// tunnel and the transport then writes the h2c preface to it.
			return nil, nil
		}
		switch strings.ToLower(selected.Scheme) {
		case "https":
			return httpsProxyAsHTTP(selected), nil
		case "socks5", "socks5h":
			// SOCKS destinations are carried by DialContext so socks5 can
			// resolve locally and socks5h can preserve the hostname.
			return nil, nil
		default:
			return selected, nil
		}
	}

	dial := wrapDialWithConnectTimeout(baseDial, connectTimeout)
	if connectTimeout <= 0 {
		dial = baseDial
	}
	if explicitProxy != nil {
		switch strings.ToLower(explicitProxy.Scheme) {
		case "socks5", "socks5h":
			transportProxy = func(*http.Request) (*url.URL, error) { return nil, nil }
			dial = newSOCKS5Dialer(baseDial, res, explicitProxy, strings.EqualFold(explicitProxy.Scheme, "socks5"), connectTimeout)
		case "https":
			if h2c {
				transportProxy = func(*http.Request) (*url.URL, error) { return nil, nil }
				dial = func(ctx context.Context, network, address string) (net.Conn, error) {
					return dialH2CProxy(ctx, baseDial, explicitProxy, address, connectTimeout)
				}
			} else {
				transportProxy = func(*http.Request) (*url.URL, error) {
					return httpsProxyAsHTTP(explicitProxy), nil
				}
				dial = newHTTPSProxyDialer(baseDial, explicitProxy, connectTimeout)
			}
		case "http":
			if h2c {
				transportProxy = func(*http.Request) (*url.URL, error) { return nil, nil }
				dial = func(ctx context.Context, network, address string) (net.Conn, error) {
					return dialH2CProxy(ctx, baseDial, explicitProxy, address, connectTimeout)
				}
			}
		}
	} else {
		// Environment proxy selection is request-specific. The wrapper below
		// carries that selection into DialContext so concurrent requests cannot
		// change one another's first hop.
		wrappedDial := dial
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			selected, ok := selectedProxy(ctx)
			if ok && selected != nil {
				switch strings.ToLower(selected.Scheme) {
				case "socks5", "socks5h":
					return newSOCKS5Dialer(baseDial, res, selected, strings.EqualFold(selected.Scheme, "socks5"), connectTimeout)(ctx, network, address)
				case "https":
					if h2c {
						return dialH2CProxy(ctx, baseDial, selected, address, connectTimeout)
					}
					return newHTTPSProxyDialer(baseDial, selected, connectTimeout)(ctx, network, address)
				case "http":
					if h2c {
						return dialH2CProxy(ctx, baseDial, selected, address, connectTimeout)
					}
				}
			}
			return wrappedDial(ctx, network, address)
		}
	}
	if h2c {
		// The h2c preface is application traffic. Clear any establishment
		// deadline before the standard transport starts the HTTP/2 stream.
		wrappedDial := dial
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := wrappedDial(ctx, network, address)
			if conn != nil {
				_ = conn.SetDeadline(time.Time{})
			}
			return conn, err
		}
	}

	rt.Proxy = transportProxy
	rt.DialContext = dial
	return rt
}

func dialH2CProxy(ctx context.Context, base func(context.Context, string, string) (net.Conn, error), proxy *url.URL, target string, timeout time.Duration) (net.Conn, error) {
	connectCtx, cancel := connectContext(ctx, timeout, "HTTP proxy connect")
	defer cancel()

	var conn net.Conn
	var err error
	if strings.EqualFold(proxy.Scheme, "https") {
		conn, err = newHTTPSProxyDialer(base, proxy, timeout)(ctx, "tcp", target)
	} else if base != nil {
		conn, err = base(connectCtx, "tcp", canonicalProxyAddress(proxy))
	} else {
		var dialer net.Dialer
		conn, err = dialer.DialContext(connectCtx, "tcp", canonicalProxyAddress(proxy))
	}
	if err != nil {
		return nil, err
	}
	if deadline, ok := connectCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	stop := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	tunneled, err := writeHTTP2CONNECT(conn, proxy, target)
	close(stop)
	<-exited
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tunneled, nil
}

func writeHTTP2CONNECT(conn net.Conn, proxy *url.URL, target string) (net.Conn, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if proxy.User != nil {
		password, _ := proxy.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(proxy.User.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("proxy CONNECT: %w", err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, fmt.Errorf("proxy CONNECT response: %w", err)
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy CONNECT returned %s", response.Status)
	}
	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: reader}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func wrapHTTP2ProxyTransport(rt *http.Transport, explicitProxy *url.URL) http.RoundTripper {
	if explicitProxy != nil {
		return rt
	}
	return &proxyTransport{base: rt, selectProxy: ProxyFunc(nil)}
}

// protocolRestrictedTransport preserves the scheme restrictions of the old
// dedicated HTTP/2 transports. A standard http.Transport without HTTP/1 in
// Protocols still handles an unsupported scheme using its HTTP/1 path, which
// would silently turn an explicit HTTP/2 request into HTTP/1.
type protocolRestrictedTransport struct {
	base   http.RoundTripper
	scheme string
}

func restrictHTTP2Scheme(base http.RoundTripper, scheme string) http.RoundTripper {
	return &protocolRestrictedTransport{base: base, scheme: scheme}
}

func (t *protocolRestrictedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil || !strings.EqualFold(req.URL.Scheme, t.scheme) {
		var scheme string
		if req != nil && req.URL != nil {
			scheme = req.URL.Scheme
		}
		return nil, fmt.Errorf("http2: unsupported scheme %q", scheme)
	}
	return t.base.RoundTrip(req)
}

func (t *protocolRestrictedTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t *protocolRestrictedTransport) Close() error {
	if closer, ok := t.base.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
