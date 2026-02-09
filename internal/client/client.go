package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/multipart"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// Client represents a wrapped HTTP client.
type Client struct {
	c *http.Client
}

// RedirectHop represents a single redirect in the chain.
type RedirectHop struct {
	Request     *http.Request  // The request that triggered the redirect
	Response    *http.Response // The redirect response (e.g., 302)
	NextRequest *http.Request  // The new request about to be made
}

// RedirectCallback is called when a redirect occurs.
type RedirectCallback func(hop RedirectHop)

// ctxRedirectCallbackKeyType is the context key type for storing redirect callback.
type ctxRedirectCallbackKeyType int

const ctxRedirectCallbackKey ctxRedirectCallbackKeyType = 1

// WithRedirectCallback returns a context with a redirect callback.
func WithRedirectCallback(ctx context.Context, cb RedirectCallback) context.Context {
	return context.WithValue(ctx, ctxRedirectCallbackKey, cb)
}

// ClientConfig represents the optional configuration parameters for a Client.
type ClientConfig struct {
	CACerts        []*x509.Certificate
	ClientCert     *tls.Certificate
	ConnectTimeout time.Duration
	DNSServer      *url.URL
	HTTP           core.HTTPVersion
	Insecure       bool
	Proxy          *url.URL
	Redirects      *int
	TLS            uint16
	UnixSocket     string
}

// NewClient returns an initialized Client given the provided configuration.
func NewClient(cfg ClientConfig) *Client {
	var proxy func(req *http.Request) (*url.URL, error)

	// Build TLS config and dial function from shared configuration.
	tlsDialCfg := &TLSDialConfig{
		CACerts:    cfg.CACerts,
		ClientCert: cfg.ClientCert,
		DNSServer:  cfg.DNSServer,
		Insecure:   cfg.Insecure,
		TLS:        cfg.TLS,
	}
	tlsConfig := tlsDialCfg.BuildTLSConfig()
	baseDial := tlsDialCfg.BuildDialContext()

	if cfg.UnixSocket != "" {
		baseDial = func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", cfg.UnixSocket)
		}
	}

	// Set the optional proxy URL.
	if cfg.Proxy != nil {
		proxy = func(r *http.Request) (*url.URL, error) {
			return cfg.Proxy, nil
		}
	}

	// Create the http.RoundTripper based on the configured HTTP version.
	var transport http.RoundTripper
	switch cfg.HTTP {
	case core.HTTP2:
		transport = getHTTP2Transport(baseDial, tlsConfig, cfg.ConnectTimeout)
	case core.HTTP3:
		transport = getHTTP3Transport(cfg.DNSServer, tlsConfig, cfg.ConnectTimeout)
	default:
		rt := &http.Transport{
			DialContext:        baseDial,
			DisableCompression: true,
			ForceAttemptHTTP2:  cfg.HTTP != core.HTTP1,
			Protocols:          &http.Protocols{},
			Proxy:              proxy,
			TLSClientConfig:    tlsConfig,
		}
		if cfg.ConnectTimeout > 0 {
			rt.DialContext = wrapDialWithConnectTimeout(baseDial, cfg.ConnectTimeout)
			rt.DialTLSContext = newDialTLSWithConnectTimeout(baseDial, tlsConfig, cfg.ConnectTimeout, cfg.HTTP != core.HTTP1)
		}
		rt.Protocols.SetHTTP1(true)
		rt.Protocols.SetHTTP2(cfg.HTTP != core.HTTP1)
		transport = rt
	}

	// Set up the redirect handler.
	client := &http.Client{Transport: transport}
	maxRedirects := -1
	if cfg.Redirects != nil {
		maxRedirects = *cfg.Redirects
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Call redirect callback if set.
		// req is the new request about to be made.
		// req.Response contains the redirect response that triggered this redirect.
		// via contains the previous requests, with via[len(via)-1] being the request
		// that received the redirect response.
		if cb, ok := req.Context().Value(ctxRedirectCallbackKey).(RedirectCallback); ok && cb != nil {
			if len(via) > 0 && req.Response != nil {
				cb(RedirectHop{
					Request:     via[len(via)-1],
					Response:    req.Response,
					NextRequest: req,
				})
			}
		}

		// Check redirect limits.
		if maxRedirects == 0 {
			return http.ErrUseLastResponse
		}
		if maxRedirects > 0 && len(via) > maxRedirects {
			return fmt.Errorf("exceeded maximum number of redirects: %d", maxRedirects)
		}
		return nil
	}

	return &Client{c: client}
}

// wrapDialWithConnectTimeout wraps a dial function with a connect timeout sub-context.
func wrapDialWithConnectTimeout(baseDial func(context.Context, string, string) (net.Conn, error), timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if baseDial != nil {
			return baseDial(ctx, network, address)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
}

// newDialTLSWithConnectTimeout returns a DialTLSContext function that performs
// DNS + TCP + TLS under a single connect timeout context. It clones the provided
// tlsConfig and sets NextProtos explicitly because http.Transport ignores
// TLSClientConfig when DialTLSContext is set.
func newDialTLSWithConnectTimeout(baseDial func(context.Context, string, string) (net.Conn, error), tlsConfig *tls.Config, timeout time.Duration, enableHTTP2 bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		dial := baseDial
		if dial == nil {
			var d net.Dialer
			dial = d.DialContext
		}

		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}

		cfg := tlsConfig.Clone()
		if enableHTTP2 {
			cfg.NextProtos = []string{"h2", "http/1.1"}
		} else {
			cfg.NextProtos = []string{"http/1.1"}
		}

		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}

		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
}

func getHTTP2Transport(baseDial func(context.Context, string, string) (net.Conn, error), tlsConfig *tls.Config, connectTimeout time.Duration) http.RoundTripper {
	return &http2.Transport{
		AllowHTTP: false, // Disable h2c, for now.
		DialTLSContext: func(ctx context.Context, network string, addr string, cfg *tls.Config) (net.Conn, error) {
			if connectTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, connectTimeout)
				defer cancel()
			}

			dial := baseDial
			if dial == nil {
				var dialer net.Dialer
				dial = dialer.DialContext
			}

			// Dial a connection and perform the TLS handshake.
			conn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			if cfg.ServerName == "" {
				c := cfg.Clone()
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					host = addr
				}
				c.ServerName = host
				cfg = c
			}

			tlsConn := tls.Client(conn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
	}
}

func getHTTP3Transport(dnsServer *url.URL, tlsConfig *tls.Config, connectTimeout time.Duration) http.RoundTripper {
	rt := &http3.Transport{
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
	}

	// Always set custom Dial to ensure trace hooks work.
	rt.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
		if connectTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, connectTimeout)
			defer cancel()
		}

		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// Resolve DNS with trace hooks.
		var ips []net.IPAddr
		if dnsServer != nil {
			if dnsServer.Scheme == "" {
				resolver := udpResolver(dnsServer.Host)
				ips, err = resolver.LookupIPAddr(ctx, host)
			} else {
				ips, portStr, err = resolveDOH(ctx, dnsServer, addr)
			}
		} else {
			// Use system resolver with trace hooks.
			ips, err = resolveWithTrace(ctx, host)
		}
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("lookup %s: no addresses found", addr)
		}

		port, err := net.LookupPort("udp", portStr)
		if err != nil {
			return nil, err
		}

		// Establish quic connection.
		trace := httptrace.ContextClientTrace(ctx)
		for _, ip := range ips {
			udpAddr := &net.UDPAddr{IP: ip.IP, Port: port}
			var lc net.ListenConfig
			var packetConn net.PacketConn
			packetConn, err = lc.ListenPacket(ctx, "udp", ":0")
			if err != nil {
				continue
			}

			if trace != nil && trace.TLSHandshakeStart != nil {
				trace.TLSHandshakeStart()
			}

			var conn *quic.Conn
			conn, err = quic.DialEarly(ctx, packetConn, udpAddr, tlsCfg, qcfg)
			if trace != nil && trace.TLSHandshakeDone != nil {
				var state tls.ConnectionState
				if conn != nil {
					state = conn.ConnectionState().TLS
				}
				trace.TLSHandshakeDone(state, err)
			}
			if err != nil {
				packetConn.Close()
				continue
			}
			return conn, nil
		}

		return nil, err
	}

	return &http3TimingTransport{rt: rt}
}

// http3TimingTransport wraps http3.Transport to provide TTFB trace hooks.
type http3TimingTransport struct {
	rt *http3.Transport
}

func (t *http3TimingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.rt.RoundTrip(req)

	// Call GotFirstResponseByte when response headers arrive.
	if err == nil {
		if trace := httptrace.ContextClientTrace(req.Context()); trace != nil {
			if trace.GotFirstResponseByte != nil {
				trace.GotFirstResponseByte()
			}
		}
	}

	return resp, err
}

// HTTPClient returns the underlying *http.Client.
func (c *Client) HTTPClient() *http.Client {
	return c.c
}

// SetJar sets the cookie jar on the HTTP client.
func (c *Client) SetJar(jar http.CookieJar) {
	c.c.Jar = jar
}

// RequestConfig represents the configuration for creating an HTTP request.
type RequestConfig struct {
	AWSSigV4    *aws.Config
	Basic       *core.KeyVal[string]
	Bearer      string
	ContentType string
	Data        io.Reader
	Form        []core.KeyVal[string]
	Headers     []core.KeyVal[string]
	HTTP        core.HTTPVersion
	Method      string
	Multipart   *multipart.Multipart
	NoEncode    bool
	QueryParams []core.KeyVal[string]
	Range       []string
	URL         *url.URL
}

// NewRequest returns an *http.Request given the provided configuration.
func (c *Client) NewRequest(ctx context.Context, cfg RequestConfig) (*http.Request, error) {
	// Add any query params to the URL.
	if len(cfg.QueryParams) > 0 {
		q := cfg.URL.Query()
		for _, kv := range cfg.QueryParams {
			q.Add(kv.Key, kv.Val)
		}
		cfg.URL.RawQuery = q.Encode()
	}

	// Set any form or multipart bodies.
	var body io.Reader
	switch {
	case cfg.Data != nil:
		body = cfg.Data
	case len(cfg.Form) > 0:
		q := make(url.Values, len(cfg.Form))
		for _, f := range cfg.Form {
			q.Add(f.Key, f.Val)
		}
		body = strings.NewReader(q.Encode())
	case cfg.Multipart != nil:
		body = cfg.Multipart
	}

	// If no scheme was provided, default to HTTPS except for loopback
	// addresses (localhost, 127.x.x.x, ::1) which default to HTTP.
	if cfg.URL.Scheme == "" {
		if IsLoopback(cfg.URL.Hostname()) {
			cfg.URL.Scheme = "http"
		} else {
			cfg.URL.Scheme = "https"
		}
	}

	// If no method was provided, default to GET.
	if cfg.Method == "" {
		cfg.Method = "GET"
	}

	// Create the initial HTTP request.
	req, err := http.NewRequestWithContext(ctx, cfg.Method, cfg.URL.String(), body)
	if err != nil {
		return nil, err
	}

	// Set the accept and user-agent headers.
	req.Header.Set("Accept", "application/json,application/vnd.msgpack,application/xml,image/webp,*/*")
	req.Header.Set("User-Agent", core.UserAgent)

	// Optionally set the content-type header.
	switch {
	case len(cfg.Form) > 0:
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case cfg.Multipart != nil:
		req.Header.Set("Content-Type", cfg.Multipart.ContentType())
	case cfg.ContentType != "":
		req.Header.Set("Content-Type", cfg.ContentType)
	}

	// Optionally set the range header.
	if len(cfg.Range) > 0 {
		req.Header.Set("Range", "bytes="+strings.Join(cfg.Range, ", "))
	}

	// Set any provided headers.
	for _, kv := range cfg.Headers {
		req.Header.Set(kv.Key, kv.Val)
	}

	// Optionally request gzip encoding.
	if !cfg.NoEncode && req.Method != "HEAD" && req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, zstd")
		ctx = context.WithValue(ctx, ctxEncodingRequestedKey, true)
		req = req.WithContext(ctx)
	}

	// Set the content-length header if the body is a file.
	setFileContentLength(req)

	// Optionally set the authorization header.
	switch {
	case cfg.AWSSigV4 != nil:
		err = aws.Sign(req, *cfg.AWSSigV4, time.Now().UTC())
		if err != nil {
			return nil, err
		}
	case cfg.Basic != nil:
		req.SetBasicAuth(cfg.Basic.Key, cfg.Basic.Val)
	case cfg.Bearer != "":
		req.Header.Set("Authorization", "Bearer "+cfg.Bearer)
	}

	return req, nil
}

// Do performs the provided http Request, returning the response.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	resp, err := c.c.Do(req)
	if err != nil {
		return nil, err
	}

	// Automatically decode the gzipped response body if we requested it.
	ce := getContentEncoding(resp.Header)
	if encodingRequested(req) && resp.Body != nil {
		if strings.EqualFold(ce, "gzip") {
			gz, err := newGZIPReader(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("gzip: %w", err)
			}
			resp.Body = gz
			resp.ContentLength = -1
		} else if strings.EqualFold(ce, "zstd") {
			zs, err := newZSTDReader(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("zstd: %w", err)
			}
			resp.Body = zs
			resp.ContentLength = -1
		}
	}

	return resp, nil
}

func getContentEncoding(h http.Header) string {
	v := h.Get("Content-Encoding")
	if v == "" {
		return ""
	}
	idx := strings.LastIndex(v, ",")
	if idx >= 0 {
		v = v[idx+1:]
	}
	return strings.TrimSpace(v)
}

// setFileContentLength sets the content-length of a request if the body is an
// *os.File that we can read of the size of.
func setFileContentLength(req *http.Request) {
	if req.ContentLength > 0 {
		return
	}

	f, ok := req.Body.(*os.File)
	if !ok {
		return
	}

	if info, err := f.Stat(); err == nil {
		req.ContentLength = info.Size()
	}
}

// ctxEncodingRequestedKeyType represents the type for storing whether gzip
// encoding was requested.
type ctxEncodingRequestedKeyType int

const ctxEncodingRequestedKey ctxEncodingRequestedKeyType = 0

// encodingRequested returns true if gzip encoding was requested for the
// provided request.
func encodingRequested(r *http.Request) bool {
	v, ok := r.Context().Value(ctxEncodingRequestedKey).(bool)
	return ok && v
}

type gzipReader struct {
	*gzip.Reader
	c io.Closer
}

// newGZIPReader returns a new io.ReadCloser that automatically decodes the
// gzipped data.
func newGZIPReader(rc io.ReadCloser) (*gzipReader, error) {
	gr, err := gzip.NewReader(rc)
	if err != nil {
		return nil, err
	}
	return &gzipReader{Reader: gr, c: rc}, nil
}

func (r *gzipReader) Close() error {
	err := r.Reader.Close()
	err2 := r.c.Close()
	if err != nil {
		return err
	}
	return err2
}

type zstdReader struct {
	*zstd.Decoder
	c io.Closer
}

func newZSTDReader(rc io.ReadCloser) (*zstdReader, error) {
	zr, err := zstd.NewReader(rc, zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxWindow(1<<23))
	if err != nil {
		return nil, err
	}
	return &zstdReader{Decoder: zr, c: rc}, nil
}

func (r *zstdReader) Close() error {
	r.Decoder.Close()
	return r.c.Close()
}

// IsLoopback returns true if the host is a loopback address.
// This includes "localhost" and IP addresses in the loopback range
// (127.0.0.0/8 for IPv4, ::1 for IPv6).
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
