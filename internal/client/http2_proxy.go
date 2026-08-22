package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"
)

// newHTTP2DialTLS returns the first-hop-aware dialer used by x/net/http2.
// Unlike http.Transport, x/net/http2.Transport has no Proxy field, so the
// CONNECT/SOCKS operation is kept here and the origin TLS configuration is
// applied only after the proxy tunnel is ready.
func newHTTP2DialTLS(base func(context.Context, string, string) (net.Conn, error), res *resolver.Resolver, explicit *url.URL, targetScheme string, originTLS *tls.Config, timeout time.Duration, echMode core.ECHMode) func(context.Context, string, string, *tls.Config) (net.Conn, error) {
	return func(ctx context.Context, network, address string, negotiated *tls.Config) (net.Conn, error) {
		target := &url.URL{Scheme: targetScheme, Host: address}
		selected, err := ProxyForURL(explicit, target)
		if err != nil {
			return nil, err
		}

		// ECH is supported only on a direct TLS connection in this task.
		// Discover the service target before dialing it; the origin name is
		// retained for SNI and HTTP authority.
		if echMode != core.ECHUnknown && echMode != core.ECHOff && selected == nil && targetScheme == "https" {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, splitErr
			}
			cfg := originTLS
			if negotiated != nil {
				cfg = negotiated
			}
			connection, discoveryErr := discoverECHForConnection(ctx, res, host, port, cfg, echMode, core.HTTP2)
			if discoveryErr != nil {
				return nil, discoveryErr
			}
			if connection.configured {
				got, dialErr := dialResolverWithECH(ctx, NewResolverDialer(res, timeout), DialRequest{
					Network: "tcp", Host: connection.targetHost, Port: connection.targetPort,
					OriginHost: host, Candidates: connection.addresses,
				}, connection.tlsConfig, echMode)
				if dialErr != nil {
					return nil, dialErr
				}
				return got.Conn, nil
			}
		}

		var conn net.Conn
		switch {
		case selected == nil:
			conn, err = dialWithBudget(ctx, base, network, address, timeout, "HTTP/2 connect")
		case strings.EqualFold(selected.Scheme, "socks5"), strings.EqualFold(selected.Scheme, "socks5h"):
			dial := newSOCKS5Dialer(base, res, selected, strings.EqualFold(selected.Scheme, "socks5"), timeout)
			conn, err = dial(ctx, network, address)
		case strings.EqualFold(selected.Scheme, "http"), strings.EqualFold(selected.Scheme, "https"):
			conn, err = dialHTTP2Proxy(ctx, base, selected, address, timeout)
		default:
			err = fmt.Errorf("unsupported proxy scheme %q", selected.Scheme)
		}
		if err != nil {
			return nil, err
		}
		if targetScheme == "http" {
			// H2C has no later TLS handshake. The connect deadline must not
			// cover the lifetime of the HTTP/2 stream.
			_ = conn.SetDeadline(time.Time{})
			return conn, nil
		}

		cfg := originTLS
		if negotiated != nil {
			cfg = negotiated
		}
		if cfg == nil {
			cfg = &tls.Config{}
		}
		cfg = cfg.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = target.Hostname()
		}
		cfg.NextProtos = []string{"h2"}
		handshakeCtx, cancel := connectContext(ctx, timeout, "HTTP/2 TLS connect")
		defer cancel()
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = tlsConn.SetDeadline(time.Time{})
		return tlsConn, nil
	}
}

func dialWithBudget(ctx context.Context, base func(context.Context, string, string) (net.Conn, error), network, address string, timeout time.Duration, phase string) (net.Conn, error) {
	connectCtx, cancel := connectContext(ctx, timeout, phase)
	defer cancel()
	conn, err := base(connectCtx, network, address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := connectCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}

func dialHTTP2Proxy(ctx context.Context, base func(context.Context, string, string) (net.Conn, error), proxy *url.URL, target string, timeout time.Duration) (net.Conn, error) {
	var conn net.Conn
	var err error
	if strings.EqualFold(proxy.Scheme, "https") {
		conn, err = newHTTPSProxyDialer(base, proxy, timeout)(ctx, "tcp", target)
	} else {
		conn, err = dialWithBudget(ctx, base, "tcp", canonicalProxyAddress(proxy), timeout, "HTTP proxy connect")
	}
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
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
	reader := bufioReader(conn)
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
	// Preserve bytes read past the CONNECT headers for the origin TLS or
	// h2c preface. A proxy is not permitted to send them, but dropping them
	// would make a malformed or eager proxy corrupt the tunnel.
	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: reader}, nil
	}
	return conn, nil
}

// bufioReader is a small adapter to keep the reader allocation at the
// protocol boundary and avoid sharing a buffered reader with the tunneled TLS
// stream. CONNECT responses end at their header boundary.
func bufioReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReader(conn)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
