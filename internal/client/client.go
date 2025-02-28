package client

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/multipart"
	"github.com/ryanfowler/fetch/internal/vars"
)

type HTTPVersion int

const (
	HTTPDefault HTTPVersion = iota
	HTTP1
	HTTP2
)

type Client struct {
	c         *http.Client
	userAgent string
}

type ClientConfig struct {
	DNSServer string
	HTTP      HTTPVersion
	Insecure  bool
	Proxy     *url.URL
	Timeout   time.Duration
	TLS       uint16
	UserAgent string
}

func NewClient(cfg ClientConfig) *Client {
	transport := &http.Transport{
		DisableCompression: true,
		Protocols:          &http.Protocols{},
		Proxy: func(r *http.Request) (*url.URL, error) {
			return cfg.Proxy, nil
		},
		TLSClientConfig: &tls.Config{},
	}

	// Set the minimum TLS version.
	if cfg.TLS == 0 {
		cfg.TLS = tls.VersionTLS12
	}
	transport.TLSClientConfig.MinVersion = cfg.TLS

	// Set optional DNS server.
	if cfg.DNSServer != "" {
		dialer := net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 10 * time.Second}
					return d.DialContext(ctx, network, cfg.DNSServer)
				},
			},
		}
		transport.DialContext = dialer.DialContext
	}

	// Set the supported protocols.
	if cfg.HTTP == HTTPDefault {
		cfg.HTTP = HTTP2
	}
	transport.Protocols.SetHTTP1(true)
	if cfg.HTTP >= HTTP2 {
		transport.Protocols.SetHTTP2(true)
		transport.Protocols.SetUnencryptedHTTP2(true)
	}

	// Accept invalid certs if insecure.
	if cfg.Insecure {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	return &Client{
		c: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
		userAgent: cfg.UserAgent,
	}
}

type RequestConfig struct {
	Method      string
	URL         *url.URL
	Form        []vars.KeyVal
	Multipart   *multipart.Multipart
	Headers     []vars.KeyVal
	QueryParams []vars.KeyVal
	Body        io.Reader
	NoEncode    bool
	AWSSigV4    *aws.Config
	Basic       *vars.KeyVal
	Bearer      string
	JSON        bool
	XML         bool
	HTTP        HTTPVersion
}

func (c *Client) NewRequest(ctx context.Context, cfg RequestConfig) (*http.Request, error) {
	q := cfg.URL.Query()
	for _, kv := range cfg.QueryParams {
		q.Add(kv.Key, kv.Val)
	}
	cfg.URL.RawQuery = q.Encode()

	switch {
	case len(cfg.Form) > 0:
		q := make(url.Values, len(cfg.Form))
		for _, f := range cfg.Form {
			q.Add(f.Key, f.Val)
		}
		cfg.Body = strings.NewReader(q.Encode())
	case cfg.Multipart != nil:
		cfg.Body = cfg.Multipart
	}

	req, err := http.NewRequestWithContext(ctx, cfg.Method, cfg.URL.String(), cfg.Body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json,application/xml,image/webp,*/*")
	req.Header.Set("User-Agent", c.userAgent)

	switch {
	case cfg.JSON:
		req.Header.Set("Content-Type", "application/json")
	case cfg.XML:
		req.Header.Set("Content-Type", "application/xml")
	}

	for _, kv := range cfg.Headers {
		req.Header.Set(kv.Key, kv.Val)
	}

	switch {
	case len(cfg.Form) > 0:
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case cfg.Multipart != nil:
		req.Header.Set("Content-Type", cfg.Multipart.ContentType())
	}

	if !cfg.NoEncode && req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip")
		ctx = context.WithValue(ctx, ctxEncodingRequestedKey, true)
		req = req.WithContext(ctx)
	}

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

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	resp, err := c.c.Do(req)
	if err != nil {
		return nil, err
	}

	ce := resp.Header.Get("Content-Encoding")
	if encodingRequested(req) && ce == "gzip" {
		gz, err := newGZIPReader(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body = gz
	}

	return resp, nil
}

type ctxEncodingRequestedKeyType int

const ctxEncodingRequestedKey ctxEncodingRequestedKeyType = 0

func encodingRequested(r *http.Request) bool {
	v, ok := r.Context().Value(ctxEncodingRequestedKey).(bool)
	return ok && v
}

type gzipReader struct {
	*gzip.Reader
	c io.Closer
}

func newGZIPReader(rc io.ReadCloser) (*gzipReader, error) {
	gzr, err := gzip.NewReader(rc)
	if err != nil {
		return nil, err
	}
	return &gzipReader{Reader: gzr, c: rc}, nil
}

func (r *gzipReader) Close() error {
	err := r.Reader.Close()
	err2 := r.c.Close()
	if err != nil {
		return err
	}
	return err2
}
