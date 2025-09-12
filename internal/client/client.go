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

// ClientConfig represents the optional configuration parameters for a Client.
type ClientConfig struct {
	CACerts    []*x509.Certificate
	DNSServer  *url.URL
	HTTP       core.HTTPVersion
	Insecure   bool
	Proxy      *url.URL
	Redirects  *int
	TLS        uint16
	UnixSocket string
}

// NewClient returns an initialized Client given the provided configuration.
func NewClient(cfg ClientConfig) *Client {
	var tlsConfig tls.Config
	var proxy func(req *http.Request) (*url.URL, error)
	var baseDial func(ctx context.Context, network, address string) (net.Conn, error)

	// Set optional DNS server.
	if cfg.DNSServer != nil {
		if cfg.DNSServer.Scheme == "" {
			baseDial = dialContextUDP(cfg.DNSServer.Host)
		} else {
			baseDial = dialContextDOH(cfg.DNSServer)
		}
	}

	if cfg.UnixSocket != "" {
		baseDial = func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", cfg.UnixSocket)
		}
	}

	// Accept invalid certs if insecure.
	if cfg.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	// Set the optinal proxy URL.
	if cfg.Proxy != nil {
		proxy = func(r *http.Request) (*url.URL, error) {
			return cfg.Proxy, nil
		}
	}

	// Set the minimum TLS version.
	if cfg.TLS == 0 {
		cfg.TLS = tls.VersionTLS12
	}
	tlsConfig.MinVersion = cfg.TLS

	// Set the RootCAs, if provided.
	if len(cfg.CACerts) > 0 {
		certPool := x509.NewCertPool()
		for _, cert := range cfg.CACerts {
			certPool.AddCert(cert)
		}
		tlsConfig.RootCAs = certPool
	}

	// Create the http.RoundTripper based on the configured HTTP version.
	var transport http.RoundTripper
	switch cfg.HTTP {
	case core.HTTP2:
		transport = getHTTP2Transport(baseDial, &tlsConfig)
	case core.HTTP3:
		transport = getHTTP3Transport(cfg.DNSServer, &tlsConfig)
	default:
		rt := &http.Transport{
			DialContext:        baseDial,
			DisableCompression: true,
			ForceAttemptHTTP2:  cfg.HTTP != core.HTTP1,
			Protocols:          &http.Protocols{},
			Proxy:              proxy,
			TLSClientConfig:    &tlsConfig,
		}
		rt.Protocols.SetHTTP1(true)
		rt.Protocols.SetHTTP2(cfg.HTTP != core.HTTP1)
		transport = rt
	}

	// Optionally set the maximum number of redirects.
	client := &http.Client{Transport: transport}
	if cfg.Redirects != nil {
		redirects := *cfg.Redirects
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if redirects == 0 {
				return http.ErrUseLastResponse
			}
			if len(via) > redirects {
				return fmt.Errorf("exceeded maximum number of redirects: %d", redirects)
			}
			return nil
		}
	}

	return &Client{c: client}
}

func getHTTP2Transport(baseDial func(context.Context, string, string) (net.Conn, error), tlsConfig *tls.Config) http.RoundTripper {
	return &http2.Transport{
		AllowHTTP: false, // Disable h2c, for now.
		DialTLSContext: func(ctx context.Context, network string, addr string, cfg *tls.Config) (net.Conn, error) {
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

func getHTTP3Transport(dnsServer *url.URL, tlsConfig *tls.Config) http.RoundTripper {
	rt := &http3.Transport{
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
	}
	if dnsServer != nil {
		rt.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			// Resolve the address to IPs.
			var ips []net.IPAddr
			var portStr string
			var err error
			if dnsServer.Scheme == "" {
				var host string
				host, portStr, err = net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				resolver := udpResolver(dnsServer.Host)
				ips, err = resolver.LookupIPAddr(ctx, host)
			} else {
				ips, portStr, err = resolveDOH(ctx, dnsServer, addr)
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
					continue
				}
				return conn, nil
			}

			return nil, err
		}
	}
	return rt
}

// RequestConfig represents the configuration for creating an HTTP request.
type RequestConfig struct {
	AWSSigV4    *aws.Config
	Basic       *core.KeyVal
	Bearer      string
	Data        io.Reader
	Form        []core.KeyVal
	Headers     []core.KeyVal
	HTTP        core.HTTPVersion
	JSON        io.Reader
	Method      string
	Multipart   *multipart.Multipart
	NoEncode    bool
	QueryParams []core.KeyVal
	Range       []string
	URL         *url.URL
	XML         io.Reader
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
	case cfg.JSON != nil:
		body = cfg.JSON
	case cfg.Multipart != nil:
		body = cfg.Multipart
	case cfg.XML != nil:
		body = cfg.XML
	}

	// If no scheme was provided, use various heuristics to choose between
	// http and https.
	if cfg.URL.Scheme == "" {
		host := cfg.URL.Hostname()
		if !strings.Contains(host, ".") || net.ParseIP(host) != nil {
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
	case cfg.JSON != nil:
		req.Header.Set("Content-Type", "application/json")
	case cfg.XML != nil:
		req.Header.Set("Content-Type", "application/xml")
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
