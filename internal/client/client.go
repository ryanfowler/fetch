package client

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/multipart"
)

// Client represents a wrapped HTTP client.
type Client struct {
	c *http.Client
}

// ClientConfig represents the optional configuration parameters for a Client.
type ClientConfig struct {
	DNSServer *url.URL
	HTTP      core.HTTPVersion
	Insecure  bool
	Proxy     *url.URL
	Redirects *int
	TLS       uint16
}

// NewClient returns an initialized Client given the provided configuration.
func NewClient(cfg ClientConfig) *Client {
	transport := &http.Transport{
		DisableCompression: true,
		Protocols:          &http.Protocols{},
		TLSClientConfig:    &tls.Config{},
	}

	// Set optional DNS server.
	if cfg.DNSServer != nil {
		if cfg.DNSServer.Scheme == "" {
			transport.DialContext = dialContextUDP(cfg.DNSServer.Host)
		} else {
			transport.DialContext = dialContextDOH(cfg.DNSServer)
		}
	}

	// Set the supported protocols.
	if cfg.HTTP == core.HTTPDefault {
		cfg.HTTP = core.HTTP2
	}
	transport.Protocols.SetHTTP1(true)
	if cfg.HTTP >= core.HTTP2 {
		transport.Protocols.SetHTTP2(true)
		transport.Protocols.SetUnencryptedHTTP2(true)
	}

	// Accept invalid certs if insecure.
	if cfg.Insecure {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	// Set the optinal proxy URL.
	if cfg.Proxy != nil {
		transport.Proxy = func(r *http.Request) (*url.URL, error) {
			return cfg.Proxy, nil
		}
	}

	// Set the minimum TLS version.
	if cfg.TLS == 0 {
		cfg.TLS = tls.VersionTLS12
	}
	transport.TLSClientConfig.MinVersion = cfg.TLS

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
	req.Header.Set("Accept", "application/json,application/xml,image/webp,*/*")
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

	// Set any provided headers.
	for _, kv := range cfg.Headers {
		req.Header.Set(kv.Key, kv.Val)
	}

	// Optionally request gzip encoding.
	if !cfg.NoEncode && req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip")
		ctx = context.WithValue(ctx, ctxEncodingRequestedKey, true)
		req = req.WithContext(ctx)
	}

	// Set the content-length header if the body is a file.
	setFileContentLength(req)

	// Optionally set the authohrization header.
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
	ce := resp.Header.Get("Content-Encoding")
	if ce == "gzip" && encodingRequested(req) {
		gz, err := newGZIPReader(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body = gz
	}

	return resp, nil
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
