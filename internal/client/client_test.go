package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	imultipart "github.com/ryanfowler/fetch/internal/multipart"
	"github.com/ryanfowler/fetch/internal/resolver"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

const (
	testEnvProxyHost = "proxy.example:8080"
	testEnvProxyURL  = "http://" + testEnvProxyHost
)

func TestMain(m *testing.M) {
	os.Setenv("HTTP_PROXY", testEnvProxyURL)
	os.Setenv("NO_PROXY", "bypass.example,localhost,127.0.0.1,::1")
	os.Unsetenv("REQUEST_METHOD")
	os.Exit(m.Run())
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		// Loopback addresses (should return true)
		{"localhost", true},
		{"LOCALHOST", true},
		{"Localhost", true},
		{"127.0.0.1", true},
		{"127.255.255.255", true},
		{"127.0.0.100", true},
		{"::1", true},

		// Non-loopback addresses (should return false)
		{"myserver", false},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"example.com", false},
		{"0.0.0.0", false},
		{"172.16.0.1", false},
		{"::2", false},
		{"2001:db8::1", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := IsLoopback(tt.host)
			if got != tt.want {
				t.Errorf("IsLoopback(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestNewRequestSetsGetBodyForMultipart(t *testing.T) {
	rawURL, err := url.Parse("https://example.com/upload")
	if err != nil {
		t.Fatal(err)
	}
	mp := imultipart.NewMultipart([]core.KeyVal[string]{
		{Key: "field", Val: "value"},
	})

	req, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{
		Method:    http.MethodPost,
		Multipart: mp,
		URL:       rawURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer req.Body.Close()

	if req.GetBody == nil {
		t.Fatal("GetBody is nil")
	}
	if ct := req.Header.Get("Content-Type"); ct != mp.ContentType() {
		t.Fatalf("Content-Type = %q, want %q", ct, mp.ContentType())
	}

	initial, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := req.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	replayed, err := io.ReadAll(replay)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(initial, replayed) {
		t.Fatal("replayed multipart body differs from initial body")
	}
}

func TestNewRequestLiteralBodyIsReplayableForDryRun(t *testing.T) {
	for name, data := range map[string]io.Reader{
		"strings": strings.NewReader("literal body"),
		"bytes":   bytes.NewReader([]byte("literal body")),
	} {
		t.Run(name, func(t *testing.T) {
			req, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{
				Data:   data,
				Method: http.MethodPost,
				URL:    mustURL(t, "https://example.com"),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer req.Body.Close()
			if req.GetBody == nil || req.ContentLength != int64(len("literal body")) {
				t.Fatalf("GetBody=%v ContentLength=%d, want replayable length %d", req.GetBody != nil, req.ContentLength, len("literal body"))
			}
			first, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			replay, err := req.GetBody()
			if err != nil {
				t.Fatal(err)
			}
			defer replay.Close()
			second, err := io.ReadAll(replay)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(first, second) {
				t.Fatalf("first=%q replay=%q", first, second)
			}
		})
	}
}

func TestNewRequestUsesLazyReplayableFileBody(t *testing.T) {
	path := t.TempDir() + "/upload.txt"
	if err := os.WriteFile(path, []byte("file body"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse("https://example.com/upload")
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{
		Data:   f,
		Method: http.MethodPut,
		URL:    u,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer req.Body.Close()

	if req.ContentLength != int64(len("file body")) || req.GetBody == nil {
		t.Fatalf("length=%d getBody=%v, want known replayable file", req.ContentLength, req.GetBody != nil)
	}
	first, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := req.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	second, err := io.ReadAll(replay)
	replay.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("first=%q replay=%q", first, second)
	}
}

func TestNewRequestDoesNotAccumulateURLDefaults(t *testing.T) {
	u := &url.URL{Host: "example.com", Path: "/path", RawQuery: "existing=one"}
	wantURL := u.String()
	c := NewClient(ClientConfig{})
	cfg := RequestConfig{
		QueryParams: []core.KeyVal[string]{{Key: "added", Val: "two words"}},
		URL:         u,
	}

	for range 2 {
		req, err := c.NewRequest(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got := req.URL.String(); got != "https://example.com/path?existing=one&added=two%20words" {
			t.Fatalf("request URL = %q", got)
		}
	}

	if got := u.String(); got != wantURL {
		t.Fatalf("input URL mutated: got %q, want %q", got, wantURL)
	}
}

func TestNewRequestValidatesFramingHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []core.KeyVal[string]
		wantErr string
	}{
		{
			name: "conflicting content lengths",
			headers: []core.KeyVal[string]{
				{Key: "Content-Length", Val: "3"},
				{Key: "content-length", Val: "4"},
			},
			wantErr: "conflicting Content-Length headers",
		},
		{
			name: "content length and transfer encoding",
			headers: []core.KeyVal[string]{
				{Key: "Content-Length", Val: "3"},
				{Key: "Transfer-Encoding", Val: "chunked"},
			},
			wantErr: "cannot be used together",
		},
		{
			name:    "unsupported transfer encoding",
			headers: []core.KeyVal[string]{{Key: "Transfer-Encoding", Val: "gzip, chunked"}},
			wantErr: "only chunked is supported",
		},
		{
			name:    "zero content length with body",
			headers: []core.KeyVal[string]{{Key: "Content-Length", Val: "0"}},
			wantErr: "cannot be used with a request body",
		},
		{
			name:    "content length smaller than body",
			headers: []core.KeyVal[string]{{Key: "Content-Length", Val: "2"}},
			wantErr: "does not match request body length 3",
		},
		{
			name:    "content length larger than body",
			headers: []core.KeyVal[string]{{Key: "Content-Length", Val: "4"}},
			wantErr: "does not match request body length 3",
		},
		{
			name:    "empty transfer encoding",
			headers: []core.KeyVal[string]{{Key: "Transfer-Encoding", Val: " , "}},
			wantErr: "must specify chunked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{
				Data:    strings.NewReader("abc"),
				Headers: tt.headers,
				URL:     mustURL(t, "https://example.com"),
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestNewRequestRejectsPositiveContentLengthWithoutBody(t *testing.T) {
	_, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{
		Headers: []core.KeyVal[string]{{Key: "Content-Length", Val: "1"}},
		URL:     mustURL(t, "https://example.com"),
	})
	if err == nil || !strings.Contains(err.Error(), "without a request body") {
		t.Fatalf("error = %v, want bodyless Content-Length error", err)
	}
}

func TestNewRequestAllowsZeroContentLengthForBodylessPost(t *testing.T) {
	req, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{
		Headers: []core.KeyVal[string]{{Key: "Content-Length", Val: "0"}},
		Method:  http.MethodPost,
		URL:     mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.Body != nil && req.Body != http.NoBody {
		t.Fatalf("body = %T, want no body", req.Body)
	}
	if req.ContentLength != 0 || req.Header.Get("Content-Length") != "0" {
		t.Fatalf("content length = %d, header = %q", req.ContentLength, req.Header.Get("Content-Length"))
	}
}

func TestNewRequestRejectsFramingThatTransportWouldStrip(t *testing.T) {
	tests := []struct {
		name   string
		method string
		header core.KeyVal[string]
		want   string
	}{
		{name: "zero length GET", method: http.MethodGet, header: core.KeyVal[string]{Key: "Content-Length", Val: "0"}, want: "is not transmitted"},
		{name: "zero length HEAD", method: http.MethodHead, header: core.KeyVal[string]{Key: "Content-Length", Val: "0"}, want: "is not transmitted"},
		{name: "bodyless chunked", method: http.MethodPost, header: core.KeyVal[string]{Key: "Transfer-Encoding", Val: "chunked"}, want: "requires a request body"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{
				Headers: []core.KeyVal[string]{tt.header},
				Method:  tt.method,
				URL:     mustURL(t, "https://example.com"),
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestExplicitRequestFramingReachesWire(t *testing.T) {
	type receivedRequest struct {
		contentLength    int64
		transferEncoding []string
		body             string
	}
	received := make(chan receivedRequest, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		received <- receivedRequest{
			contentLength:    r.ContentLength,
			transferEncoding: slices.Clone(r.TransferEncoding),
			body:             string(data),
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	c := NewClient(ClientConfig{})
	defer c.Close()
	tests := []struct {
		name     string
		cfg      RequestConfig
		wantCL   int64
		wantTE   []string
		wantBody string
	}{
		{
			name: "zero-length POST",
			cfg: RequestConfig{
				Headers: []core.KeyVal[string]{{Key: "Content-Length", Val: "0"}},
				Method:  http.MethodPost,
			},
			wantCL: 0,
		},
		{
			name: "chunked body",
			cfg: RequestConfig{
				Data:    strings.NewReader("abc"),
				Headers: []core.KeyVal[string]{{Key: "Transfer-Encoding", Val: "chunked"}},
				Method:  http.MethodPost,
			},
			wantCL:   -1,
			wantTE:   []string{"chunked"},
			wantBody: "abc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.URL = mustURL(t, server.URL)
			req, err := c.NewRequest(context.Background(), tt.cfg)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			got := <-received
			if got.contentLength != tt.wantCL || !slices.Equal(got.transferEncoding, tt.wantTE) || got.body != tt.wantBody {
				t.Fatalf("wire framing = length %d, encodings %q, body %q", got.contentLength, got.transferEncoding, got.body)
			}
		})
	}
}

func TestNewRequestNormalizesSafeFramingHeaders(t *testing.T) {
	req, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{
		Data: strings.NewReader("abc"),
		Headers: []core.KeyVal[string]{
			{Key: "Content-Length", Val: "3"},
			{Key: "content-length", Val: "3"},
		},
		URL: mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer req.Body.Close()
	if req.ContentLength != 3 || !slices.Equal(req.Header.Values("Content-Length"), []string{"3"}) {
		t.Fatalf("content length = %d, headers = %q", req.ContentLength, req.Header.Values("Content-Length"))
	}

	chunked, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{
		Data:    strings.NewReader("abc"),
		Headers: []core.KeyVal[string]{{Key: "Transfer-Encoding", Val: "CHUNKED"}},
		URL:     mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer chunked.Body.Close()
	if chunked.ContentLength != -1 || !slices.Equal(chunked.TransferEncoding, []string{"chunked"}) {
		t.Fatalf("chunked framing = length %d, encodings %q", chunked.ContentLength, chunked.TransferEncoding)
	}
}

func TestNewRequestRejectsNilURL(t *testing.T) {
	_, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{})
	if err == nil || err.Error() != "request URL is required" {
		t.Fatalf("error = %v, want request URL is required", err)
	}
}

func TestCLI003RequestDefaultsAndOrdering(t *testing.T) {
	u, err := url.Parse("https://example.com/path?z=old&space=hello+world")
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(ClientConfig{})

	req, err := c.NewRequest(context.Background(), RequestConfig{
		Data: strings.NewReader("body"),
		Headers: []core.KeyVal[string]{
			{Key: "X-Test", Val: "one"},
			{Key: "Accept", Val: "application/xml"},
			{Key: "X-Test", Val: "two"},
		},
		QueryParams: []core.KeyVal[string]{
			{Key: "a", Val: "one"},
			{Key: "z", Val: "two"},
			{Key: "space", Val: " hello "},
		},
		URL: u,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer req.Body.Close()

	if req.Method != http.MethodPost {
		t.Fatalf("method = %q, want POST", req.Method)
	}
	if got := req.Header.Values("X-Test"); !slices.Equal(got, []string{"one", "two"}) {
		t.Fatalf("X-Test values = %q, want [one two]", got)
	}
	if got := req.Header.Get("Accept"); got != "application/xml" {
		t.Fatalf("Accept = %q, want explicit value", got)
	}
	if got := req.Header.Get("Accept-Encoding"); got != "gzip, br, zstd" {
		t.Fatalf("Accept-Encoding = %q, want gzip, br, zstd", got)
	}
	withoutEncoding, err := c.NewRequest(context.Background(), RequestConfig{
		Headers: []core.KeyVal[string]{{Key: "Accept-Encoding", Val: ""}},
		URL:     mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := withoutEncoding.Header.Values("Accept-Encoding"); !slices.Equal(got, []string{""}) {
		t.Fatalf("explicit empty Accept-Encoding = %q, want empty value", got)
	}
	if got := req.URL.RawQuery; got != "z=old&space=hello+world&a=one&z=two&space=%20hello%20" {
		t.Fatalf("RawQuery = %q, want appended order and preserved spaces", got)
	}

	article, err := c.NewRequest(context.Background(), RequestConfig{Article: true, URL: mustURL(t, "https://example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if got := article.Header.Get("Accept"); got != "text/html, application/xhtml+xml;q=0.9, text/markdown;q=0.8, */*;q=0.1" {
		t.Fatalf("article Accept = %q", got)
	}

	explicitGet, err := c.NewRequest(context.Background(), RequestConfig{
		Data:   strings.NewReader("body"),
		Method: http.MethodGet,
		URL:    mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer explicitGet.Body.Close()
	if explicitGet.Method != http.MethodGet {
		t.Fatalf("explicit method = %q, want GET", explicitGet.Method)
	}
}

func TestApplyJarCookiesAddsEffectiveDryRunCookies(t *testing.T) {
	u := mustURL(t, "https://example.com/path")
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "secret"}})

	c := NewClient(ClientConfig{})
	c.SetJar(jar)
	req, err := c.NewRequest(context.Background(), RequestConfig{URL: u})
	if err != nil {
		t.Fatal(err)
	}
	req = c.ApplyJarCookies(req)
	if got := req.Header.Get("Cookie"); got != "session=secret" {
		t.Fatalf("Cookie = %q, want session=secret", got)
	}
}

func TestNewRequestConvertsURLUserinfoToBasicAuth(t *testing.T) {
	u := mustURL(t, "https://url%20user:open%20sesame@example.com/path")
	req, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{URL: u})
	if err != nil {
		t.Fatal(err)
	}
	if u.User != nil || req.URL.User != nil {
		t.Fatal("URL userinfo was not removed")
	}
	username, password, ok := req.BasicAuth()
	if !ok || username != "url user" || password != "open sesame" {
		t.Fatalf("Basic auth = %q:%q, %v", username, password, ok)
	}
	if got := req.URL.String(); got != "https://example.com/path" {
		t.Fatalf("request URL = %q, want userinfo-free URL", got)
	}
}

func TestNewRequestExplicitAuthorizationOverridesURLUserinfo(t *testing.T) {
	req, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{
		Headers: []core.KeyVal[string]{{Key: "Authorization", Val: "Bearer explicit"}},
		URL:     mustURL(t, "https://user:password@example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer explicit" {
		t.Fatalf("Authorization = %q, want explicit header", got)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestDoClosesResponseBodyWhenDecoderConstructionFails(t *testing.T) {
	body := &trackingReadCloser{
		Reader: bytes.NewReader([]byte("not a valid compressed body")),
	}
	c := &Client{
		c: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header: http.Header{
						"Content-Encoding": []string{"gzip"},
					},
					Body:    body,
					Request: req,
				}, nil
			}),
		},
	}
	req, err := http.NewRequestWithContext(
		context.WithValue(context.Background(), ctxEncodingRequestedKey, true),
		http.MethodGet,
		"https://example.com",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.Do(req)
	if err == nil {
		t.Fatal("expected decoder construction error")
	}
	if resp != nil {
		t.Fatalf("response = %v, want nil", resp)
	}
	if !strings.Contains(err.Error(), "gzip:") {
		t.Fatalf("error = %q, want prefix containing %q", err, "gzip:")
	}
	if !body.closed {
		t.Fatal("response body was not closed")
	}
}

func TestDoDecodesBrotliContentEncoding(t *testing.T) {
	const data = "this is Brotli encoded data"
	// Keep the encoded fixture constant so this test does not need a second
	// Brotli dependency.
	body := []byte("\x0b\x0d\x80this is Brotli encoded data\x03")
	c := &Client{
		c: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header: http.Header{
						"Content-Encoding": []string{"br"},
					},
					Body:    io.NopCloser(bytes.NewReader(body)),
					Request: req,
				}, nil
			}),
		},
	}
	req, err := c.NewRequest(context.Background(), RequestConfig{
		Compression: core.CompressionAuto,
		URL:         mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	decoded, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != data {
		t.Fatalf("decoded body = %q, want %q", decoded, data)
	}
}

func TestDoDecodesStackedContentEncodingInReverseOrder(t *testing.T) {
	const data = "this is stacked encoded data"
	body := zstdEncode(t, gzipEncode(t, []byte(data)))
	c := &Client{
		c: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header: http.Header{
						"Content-Encoding": []string{"gzip, zstd"},
					},
					Body:    io.NopCloser(bytes.NewReader(body)),
					Request: req,
				}, nil
			}),
		},
	}
	req, err := c.NewRequest(context.Background(), RequestConfig{
		Compression: core.CompressionAuto,
		URL:         mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != data {
		t.Fatalf("body = %q, want %q", got, data)
	}
}

func TestDoDecodesMultipleContentEncodingHeaderValues(t *testing.T) {
	const data = "this is multiply header encoded data"
	body := zstdEncode(t, gzipEncode(t, []byte(data)))
	c := &Client{
		c: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header: http.Header{
						"Content-Encoding": []string{"gzip", "zstd"},
					},
					Body:    io.NopCloser(bytes.NewReader(body)),
					Request: req,
				}, nil
			}),
		},
	}
	req, err := c.NewRequest(context.Background(), RequestConfig{
		Compression: core.CompressionAuto,
		URL:         mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != data {
		t.Fatalf("body = %q, want %q", got, data)
	}
}

func TestDoLeavesUnknownStackedContentEncodingUntouched(t *testing.T) {
	body := []byte("not decoded")
	c := &Client{
		c: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header: http.Header{
						"Content-Encoding": []string{"unknown, gzip"},
					},
					Body:    io.NopCloser(bytes.NewReader(body)),
					Request: req,
				}, nil
			}),
		},
	}
	req := newEncodingRequestedRequest(t)

	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body = %q, want %q", got, body)
	}
}

func TestRequestObserversComposeWithoutRecursion(t *testing.T) {
	var first, second int
	ctx := WithRequestObserver(context.Background(), func(*http.Request) { first++ })
	ctx = WithRequestObserver(ctx, func(*http.Request) { second++ })
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	requestObserver(req.Context())(req)
	if first != 1 || second != 1 {
		t.Fatalf("observer calls = (%d, %d), want (1, 1)", first, second)
	}
}

func TestRedirectMethodAndBodySemantics(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		method     string
		body       string
		wantMethod string
		wantBody   string
	}{
		{name: "301 PUT", status: http.StatusMovedPermanently, method: http.MethodPut, body: "put", wantMethod: http.MethodPut, wantBody: "put"},
		{name: "302 PATCH", status: http.StatusFound, method: http.MethodPatch, body: "patch", wantMethod: http.MethodPatch, wantBody: "patch"},
		{name: "301 POST", status: http.StatusMovedPermanently, method: http.MethodPost, body: "post", wantMethod: http.MethodGet},
		{name: "302 POST", status: http.StatusFound, method: http.MethodPost, body: "post", wantMethod: http.MethodGet},
		{name: "303 POST", status: http.StatusSeeOther, method: http.MethodPost, body: "post", wantMethod: http.MethodGet},
		{name: "303 HEAD", status: http.StatusSeeOther, method: http.MethodHead, wantMethod: http.MethodHead},
		{name: "307 PUT", status: http.StatusTemporaryRedirect, method: http.MethodPut, body: "put", wantMethod: http.MethodPut, wantBody: "put"},
		{name: "308 PATCH", status: http.StatusPermanentRedirect, method: http.MethodPatch, body: "patch", wantMethod: http.MethodPatch, wantBody: "patch"},
		{name: "301 custom", status: http.StatusMovedPermanently, method: "PROPFIND", body: "custom-301", wantMethod: "PROPFIND", wantBody: "custom-301"},
		{name: "302 custom", status: http.StatusFound, method: "PROPFIND", body: "custom-302", wantMethod: "PROPFIND", wantBody: "custom-302"},
		{name: "307 custom", status: http.StatusTemporaryRedirect, method: "PROPFIND", body: "custom-307", wantMethod: "PROPFIND", wantBody: "custom-307"},
		{name: "308 custom", status: http.StatusPermanentRedirect, method: "PROPFIND", body: "custom-308", wantMethod: "PROPFIND", wantBody: "custom-308"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotMethod, gotBody, gotContentType string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					http.Redirect(w, r, "/final", tt.status)
					return
				}
				gotMethod = r.Method
				gotContentType = r.Header.Get("Content-Type")
				if tt.wantBody == "" {
					for _, name := range []string{"Content-Length", "Transfer-Encoding", "Content-Encoding"} {
						if value := r.Header.Get(name); value != "" {
							t.Errorf("%s survived bodyless redirect: %q", name, value)
						}
					}
				}
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read final body: %v", err)
				}
				gotBody = string(data)
			}))
			defer server.Close()

			req, err := http.NewRequest(tt.method, server.URL+"/start", strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/test")
			resp, err := NewClient(ClientConfig{}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			if gotMethod != tt.wantMethod {
				t.Fatalf("final method = %q, want %q", gotMethod, tt.wantMethod)
			}
			if gotBody != tt.wantBody {
				t.Fatalf("final body = %q, want %q", gotBody, tt.wantBody)
			}
			if tt.wantBody == "" && gotContentType != "" {
				t.Fatalf("body header survived rewrite: Content-Type=%q", gotContentType)
			}
			if tt.wantBody != "" && gotContentType != "application/test" {
				t.Fatalf("Content-Type = %q, want application/test", gotContentType)
			}
		})
	}
}

func TestCrossOriginRedirectBodyIsRefused(t *testing.T) {
	tests := []struct {
		status      int
		method      string
		wantRefused bool
	}{
		{status: http.StatusMovedPermanently, method: http.MethodPost},
		{status: http.StatusFound, method: http.MethodPost},
		{status: http.StatusTemporaryRedirect, method: http.MethodPost, wantRefused: true},
		{status: http.StatusPermanentRedirect, method: http.MethodPost, wantRefused: true},
	}
	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		for _, method := range []string{
			http.MethodGet,
			http.MethodHead,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
			"PROPFIND",
		} {
			tests = append(tests, struct {
				status      int
				method      string
				wantRefused bool
			}{status: status, method: method, wantRefused: true})
		}
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%d %s", tt.status, tt.method)
		t.Run(name, func(t *testing.T) {
			var targetCalls, targetBytes int
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetCalls++
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read target body: %v", err)
				}
				targetBytes += len(body)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer target.Close()

			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+"/final", tt.status)
			}))
			defer source.Close()

			req, err := http.NewRequest(tt.method, source.URL+"/start", strings.NewReader("secret-body"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := NewClient(ClientConfig{}).Do(req)
			if tt.wantRefused {
				if err == nil || !strings.Contains(err.Error(), "refusing cross-origin redirect with request body") {
					t.Fatalf("error = %v, want cross-origin body refusal", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if targetCalls != 1 || targetBytes != 0 {
					t.Fatalf("target received %d requests and %d body bytes, want 1 request and 0 bytes", targetCalls, targetBytes)
				}
			}
			if tt.wantRefused && (targetCalls != 0 || targetBytes != 0) {
				t.Fatalf("target received %d requests and %d body bytes, want none", targetCalls, targetBytes)
			}
		})
	}
}

func TestRedirectHookCannotSendBodyToCrossOriginURL(t *testing.T) {
	hooks := []struct {
		name string
		wrap func(context.Context, *url.URL) context.Context
	}{
		{
			name: "observer",
			wrap: func(ctx context.Context, targetURL *url.URL) context.Context {
				return WithRequestObserver(ctx, func(req *http.Request) {
					if req.Response != nil {
						req.URL = targetURL
					}
				})
			},
		},
		{
			name: "observer clears response after changing body",
			wrap: func(ctx context.Context, targetURL *url.URL) context.Context {
				return WithRequestObserver(ctx, func(req *http.Request) {
					if req.Response != nil {
						req.URL = targetURL
						req.Body = io.NopCloser(strings.NewReader("hook-body"))
						req.Response = nil
					}
				})
			},
		},
		{
			name: "validator",
			wrap: func(ctx context.Context, targetURL *url.URL) context.Context {
				return WithRedirectValidator(ctx, func(hop RedirectHop) error {
					hop.NextRequest.URL = targetURL
					return nil
				})
			},
		},
		{
			name: "callback",
			wrap: func(ctx context.Context, targetURL *url.URL) context.Context {
				return WithRedirectCallback(ctx, func(hop RedirectHop) {
					hop.NextRequest.URL = targetURL
				})
			},
		},
	}

	for _, hook := range hooks {
		t.Run(hook.name, func(t *testing.T) {
			var targetCalls int
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetCalls++
				w.WriteHeader(http.StatusNoContent)
			}))
			defer target.Close()
			targetURL, err := url.Parse(target.URL + "/final")
			if err != nil {
				t.Fatal(err)
			}

			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/middle", http.StatusTemporaryRedirect)
			}))
			defer source.Close()

			req, err := http.NewRequest(http.MethodPut, source.URL+"/start", strings.NewReader("secret-body"))
			if err != nil {
				t.Fatal(err)
			}
			req = req.WithContext(hook.wrap(req.Context(), targetURL))
			_, err = NewClient(ClientConfig{}).Do(req)
			if err == nil || !strings.Contains(err.Error(), "refusing cross-origin redirect with request body") {
				t.Fatalf("error = %v, want cross-origin body refusal", err)
			}
			if targetCalls != 0 {
				t.Fatalf("target received %d requests, want none", targetCalls)
			}
		})
	}
}

func TestRedirectLocationUserinfoIsStripped(t *testing.T) {
	var gotURL *url.URL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "http://user:password@"+r.Host+"/final", http.StatusFound)
			return
		}
		gotURL = r.URL
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewClient(ClientConfig{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotURL == nil {
		t.Fatal("redirect target was not reached")
	}
	if gotURL.User != nil {
		t.Fatalf("redirect request URL userinfo = %v, want nil", gotURL.User)
	}
}

func TestRedirectCrossOriginStripsCredentialsAndHost(t *testing.T) {
	var got http.Header
	var gotHost string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		gotHost = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/final", http.StatusFound)
	}))
	defer source.Close()

	req, err := http.NewRequest(http.MethodGet, source.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("user", "secret")
	req.Header.Set("Cookie", "session=origin")
	req.Header.Set("Proxy-Authorization", "Basic cHJveHk6c2VjcmV0")
	req.Host = "virtual-origin.invalid"

	resp, err := NewClient(ClientConfig{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		if value := got.Get(name); value != "" {
			t.Errorf("cross-origin %s = %q, want empty", name, value)
		}
	}
	if gotHost == "virtual-origin.invalid" {
		t.Fatalf("cross-origin Host was preserved: %q", gotHost)
	}
}

func TestRedirectCrossOriginStripsManualCookieWithoutJar(t *testing.T) {
	var received string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/final", http.StatusFound)
	}))
	defer source.Close()

	req, err := http.NewRequest(http.MethodGet, source.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", "session=origin-secret")
	resp, err := NewClient(ClientConfig{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if received != "" {
		t.Fatalf("cross-origin Cookie = %q, want empty", received)
	}
}

func TestRedirectObserverCannotRestoreCrossOriginPolicy(t *testing.T) {
	var got http.Header
	var gotHost string
	var source, target *httptest.Server
	source = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, target.URL+"/final", http.StatusFound)
			return
		}
		got = r.Header.Clone()
		gotHost = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer source.Close()
	target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, source.URL+"/observer-final", http.StatusFound)
	}))
	defer target.Close()

	req, err := http.NewRequest(http.MethodGet, source.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", "origin-secret")
	req.Header.Set("X-Trace-ID", "trace-id")
	req.Host = "virtual-origin.invalid"
	req = req.WithContext(WithRequestObserver(req.Context(), func(next *http.Request) {
		if next.Response == nil {
			return
		}
		// Simulate a hook that tries to undo the policy by routing back to the
		// initial origin, restoring Host, and dropping the security context.
		u, _ := url.Parse(source.URL + "/observer-final")
		next.URL = u
		next.Host = "restored.invalid"
		next.Header.Set("X-API-Key", "observer-secret")
		*next = *next.WithContext(context.Background())
	}))

	resp, err := NewClient(ClientConfig{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got.Get("X-API-Key") != "" {
		t.Fatalf("observer-restored credential = %q, want empty", got.Get("X-API-Key"))
	}
	if got.Get("X-Trace-ID") != "trace-id" {
		t.Fatalf("ordinary header = %q, want trace-id", got.Get("X-Trace-ID"))
	}
	if gotHost == "restored.invalid" {
		t.Fatalf("observer-restored Host = %q", gotHost)
	}
}

func TestRedirectCredentialHeaderProvenanceAndClassification(t *testing.T) {
	tests := map[string]bool{
		"Authorization":       true,
		"X-Authentication":    true,
		"X-API-Key":           true,
		"X-ApiKey":            true,
		"X-AuthToken":         true,
		"X-ClientSecret":      true,
		"X-Client-ID":         true,
		"X-PrivateKey":        true,
		"X-Private-Value":     true,
		"x-aPiKey":            true,
		"X-rEqUeStSiGnAtUrE":  true,
		"x-cLiEnTiD":          true,
		"X-Keyboard-Layout":   false,
		"X-KeyboardLayout":    false,
		"X-Client-Identifier": false,
		"X-Trace-ID":          false,
	}
	for name, want := range tests {
		if got := isRedirectCredentialHeader(name); got != want {
			t.Errorf("isRedirectCredentialHeader(%q) = %v, want %v", name, got, want)
		}
	}

	var got http.Header
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/final", http.StatusFound)
	}))
	defer source.Close()

	req, err := http.NewRequest(http.MethodGet, source.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Account-Value", "user-secret")
	req = req.WithContext(WithCredentialHeaders(req.Context(), "X-Account-Value"))
	req = req.WithContext(WithRequestObserver(req.Context(), func(next *http.Request) {
		if next.Response != nil {
			next.Header.Set("X-Generated-Value", "generated-secret")
			MarkCredentialHeaders(next, "X-Generated-Value")
		}
	}))
	resp, err := NewClient(ClientConfig{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, name := range []string{"X-Account-Value", "X-Generated-Value"} {
		if got.Get(name) != "" {
			t.Fatalf("unclassified credential header %s = %q, want empty", name, got.Get(name))
		}
	}
}

func TestInitialObserverContextReplacementPreservesCredentialProvenance(t *testing.T) {
	var got http.Header
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/final", http.StatusFound)
	}))
	defer source.Close()

	req, err := http.NewRequest(http.MethodGet, source.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Account-Value", "origin-secret")
	req = req.WithContext(WithCredentialHeaders(req.Context(), "X-Account-Value"))
	req = req.WithContext(WithRequestObserver(req.Context(), func(next *http.Request) {
		if next.Response == nil {
			*next = *next.WithContext(context.Background())
		}
	}))

	resp, err := NewClient(ClientConfig{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got.Get("X-Account-Value") != "" {
		t.Fatalf("unclassified credential header = %q, want empty", got.Get("X-Account-Value"))
	}
}

func TestNewRequestMarksCompoundCredentialHeaderProvenance(t *testing.T) {
	client := NewClient(ClientConfig{})
	defer client.Close()

	initialURL := mustURL(t, "http://origin.example/start")
	req, err := client.NewRequest(context.Background(), RequestConfig{
		URL: initialURL,
		Headers: []core.KeyVal[string]{
			{Key: "X-ClientID", Val: "client-id"},
			{Key: "X-KeyboardLayout", Val: "keyboard-layout"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := req.Clone(req.Context())
	req.URL = mustURL(t, "http://target.example/final")
	applyRedirectCredentialPolicy(req, []*http.Request{initial}, nil)

	if got := req.Header.Get("X-ClientID"); got != "" {
		t.Fatalf("compound credential header = %q, want empty", got)
	}
	if got := req.Header.Get("X-KeyboardLayout"); got != "keyboard-layout" {
		t.Fatalf("ordinary compound header = %q, want keyboard-layout", got)
	}
}

func TestRedirectCustomCredentialHeadersByOriginAndStatus(t *testing.T) {
	tests := []struct {
		name       string
		sourceTLS  bool
		targetTLS  bool
		hostChange bool
	}{
		{name: "HTTP to HTTP port change"},
		{name: "HTTP to HTTPS", targetTLS: true},
		{name: "HTTPS to HTTP", sourceTLS: true},
		{name: "HTTP host change", hostChange: true},
	}
	statuses := []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	}

	for _, test := range tests {
		for _, status := range statuses {
			t.Run(fmt.Sprintf("%s/%d", test.name, status), func(t *testing.T) {
				var got http.Header
				target := newRedirectTestServer(t, test.targetTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					got = r.Header.Clone()
					w.WriteHeader(http.StatusNoContent)
				}))
				targetURL := target.URL + "/final"
				if test.hostChange {
					targetURL = strings.Replace(targetURL, "127.0.0.1", "localhost", 1)
				}
				source := newRedirectTestServer(t, test.sourceTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, targetURL, status)
				}))

				req, err := http.NewRequest(http.MethodGet, source.URL+"/start", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("X-API-Key", "user-api-key")
				req.Header.Set("X-ApiKey", "user-api-key-compound")
				req.Header.Set("X-Auth-Token", "user-auth-token")
				req.Header.Set("X-AuthToken", "user-auth-token-compound")
				req.Header.Set("X-Client-Secret", "user-client-secret")
				req.Header.Set("X-ClientSecret", "user-client-secret-compound")
				req.Header.Set("X-Request-Signature", "user-signature")
				req.Header.Set("X-PrivateKey", "user-private-key")
				req.Header.Set("X-Trace-ID", "trace-id")
				req.Header.Set("X-KeyboardLayout", "keyboard-layout")

				var observedRedirectHeaders []http.Header
				ctx := WithRequestObserver(req.Context(), func(next *http.Request) {
					if next.Response == nil {
						next.Header.Set("X-Generated-Token", "generated-token")
						return
					}
					observedRedirectHeaders = append(observedRedirectHeaders, next.Header.Clone())
					// Simulate a request signer that generates the header after the
					// redirect policy has run. The transport must still strip it.
					next.Header.Set("X-Generated-Token", "generated-token")
				})
				req = req.WithContext(ctx)

				client := NewClient(ClientConfig{Insecure: true})
				defer client.Close()
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()

				for _, name := range []string{
					"X-API-Key", "X-ApiKey", "X-Auth-Token", "X-AuthToken", "X-Client-Secret", "X-ClientSecret",
					"X-Request-Signature", "X-PrivateKey", "X-Generated-Token",
				} {
					if value := got.Get(name); value != "" {
						t.Errorf("cross-origin %s = %q, want empty", name, value)
					}
				}
				if got.Get("X-Trace-ID") != "trace-id" {
					t.Errorf("non-credential custom header = %q, want trace-id", got.Get("X-Trace-ID"))
				}
				if got.Get("X-KeyboardLayout") != "keyboard-layout" {
					t.Errorf("ordinary compound header = %q, want keyboard-layout", got.Get("X-KeyboardLayout"))
				}
				if len(observedRedirectHeaders) != 1 {
					t.Fatalf("redirect observer calls = %d, want 1", len(observedRedirectHeaders))
				}
				for _, name := range []string{
					"X-API-Key", "X-ApiKey", "X-Auth-Token", "X-AuthToken", "X-Client-Secret", "X-ClientSecret",
					"X-Request-Signature", "X-PrivateKey", "X-Generated-Token",
				} {
					if value := observedRedirectHeaders[0].Get(name); value != "" {
						t.Errorf("observer saw cross-origin %s = %q, want empty", name, value)
					}
				}
			})
		}
	}
}

func TestRedirectCustomCredentialHeadersAreNotRestored(t *testing.T) {
	var final http.Header
	var source *httptest.Server
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, source.URL+"/final", http.StatusFound)
	}))
	defer target.Close()
	source = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, target.URL+"/middle", http.StatusFound)
			return
		}
		final = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer source.Close()

	req, err := http.NewRequest(http.MethodGet, source.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", "user-api-key")
	req.Header.Set("X-Trace-ID", "trace-id")
	req = req.WithContext(WithRequestObserver(req.Context(), func(next *http.Request) {
		if next.Response == nil {
			next.Header.Set("X-Generated-Token", "generated-token")
		}
	}))

	client := NewClient(ClientConfig{Insecure: true})
	defer client.Close()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	for _, name := range []string{"X-API-Key", "X-Generated-Token"} {
		if value := final.Get(name); value != "" {
			t.Errorf("credential %s was restored after returning to the original origin: %q", name, value)
		}
	}
	if final.Get("X-Trace-ID") != "trace-id" {
		t.Fatalf("non-credential custom header = %q, want trace-id", final.Get("X-Trace-ID"))
	}
}

func TestMTLSRedirectsRejectCrossOriginBeforeDestinationHandshake(t *testing.T) {
	statuses := []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	}

	for _, status := range statuses {
		t.Run(fmt.Sprintf("%d", status), func(t *testing.T) {
			var targetHandshakes atomic.Int64
			var targetRequests, targetCertificates int
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetRequests++
				if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
					targetCertificates++
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			target.TLS = &tls.Config{
				ClientAuth: tls.RequireAnyClientCert,
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					targetHandshakes.Add(1)
					return nil, nil
				},
			}
			target.StartTLS()
			defer target.Close()

			source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+"/final", status)
			}))
			defer source.Close()

			req, err := http.NewRequest(http.MethodGet, source.URL+"/start", nil)
			if err != nil {
				t.Fatal(err)
			}
			client := NewClient(ClientConfig{
				ClientCert: newTestClientCertificate(t),
				HTTP:       core.HTTP1,
				Insecure:   true,
			})
			defer client.Close()

			resp, err := client.Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			if err == nil {
				t.Fatal("cross-origin mTLS redirect succeeded, want refusal")
			}
			if !strings.Contains(err.Error(), "cross-origin redirect") {
				t.Fatalf("error = %q, want cross-origin redirect refusal", err)
			}
			if handshakes := targetHandshakes.Load(); handshakes != 0 {
				t.Fatalf("destination TLS handshakes = %d, want 0", handshakes)
			}
			if targetRequests != 0 || targetCertificates != 0 {
				t.Fatalf("destination requests/certificates = %d/%d, want 0/0", targetRequests, targetCertificates)
			}
		})
	}
}

func TestMTLSSameOriginRedirectsRemainAllowed(t *testing.T) {
	statuses := []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	}

	for _, status := range statuses {
		t.Run(fmt.Sprintf("%d", status), func(t *testing.T) {
			var finalCertificates int
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					http.Redirect(w, r, "/final", status)
					return
				}
				if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
					finalCertificates++
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
			server.StartTLS()
			defer server.Close()

			req, err := http.NewRequest(http.MethodGet, server.URL+"/start", nil)
			if err != nil {
				t.Fatal(err)
			}
			client := NewClient(ClientConfig{
				ClientCert: newTestClientCertificate(t),
				HTTP:       core.HTTP1,
				Insecure:   true,
			})
			defer client.Close()

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
			}
			if finalCertificates != 1 {
				t.Fatalf("same-origin destination certificates = %d, want 1", finalCertificates)
			}
		})
	}
}

func newTestClientCertificate(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fetch-test-client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newRedirectTestServer(t *testing.T, tlsEnabled bool, handler http.Handler) *httptest.Server {
	t.Helper()
	if tlsEnabled {
		return httptest.NewTLSServer(handler)
	}
	return httptest.NewServer(handler)
}

func TestCrossOriginRedirectsKeepSharedTransport(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/final", http.StatusFound)
	}))
	defer source.Close()

	c := NewClient(ClientConfig{})
	defer c.Close()
	transport := c.HTTPClient().Transport

	const requests = 32
	errs := make(chan error, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.HTTPClient().Get(source.URL + "/start")
			if err == nil {
				err = resp.Body.Close()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := c.HTTPClient().Transport; got != transport {
		t.Fatalf("transport changed across redirects: got %T %p, want %T %p", got, got, transport, transport)
	}
}

func TestRedirectBodylessMethodSurvivesLaterRedirect(t *testing.T) {
	var gotMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/middle", http.StatusMovedPermanently)
		case "/middle":
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
		default:
			gotMethod = r.Method
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/start", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewClient(ClientConfig{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotMethod != http.MethodGet {
		t.Fatalf("final method = %q, want GET", gotMethod)
	}
}

func TestRedirectBodySurvivesEarlierMethodPreservingHop(t *testing.T) {
	var gotMethod, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/middle", http.StatusFound)
		case "/middle":
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
		default:
			gotMethod = r.Method
			body, _ := io.ReadAll(r.Body)
			gotBody = string(body)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodPut, server.URL+"/start", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewClient(ClientConfig{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotMethod != http.MethodPut || gotBody != "body" {
		t.Fatalf("final request = %s %q, want PUT body", gotMethod, gotBody)
	}
}

func TestRedirectCookieJarDoesNotLeakAcrossPorts(t *testing.T) {
	var received string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "updated"})
		http.Redirect(w, r, target.URL+"/final", http.StatusFound)
	}))
	defer source.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceURL, err := url.Parse(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(sourceURL, []*http.Cookie{{Name: "session", Value: "source"}})
	c := NewClient(ClientConfig{})
	c.SetJar(jar)
	req, err := http.NewRequest(http.MethodGet, source.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if received != "" {
		t.Fatalf("cross-port Cookie = %q, want empty", received)
	}
}

func TestRedirectCookieJarDoesNotLeakWithoutSetCookie(t *testing.T) {
	var received *http.Request
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/app/final", http.StatusFound)
	}))
	defer source.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceURL, err := url.Parse(source.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	destinationURL, err := url.Parse(target.URL + "/app/final")
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(sourceURL, []*http.Cookie{{Name: "source", Value: "secret", Path: "/"}})
	jar.SetCookies(destinationURL, []*http.Cookie{{Name: "destination", Value: "valid", Path: "/app"}})

	c := NewClient(ClientConfig{})
	defer c.Close()
	c.SetJar(jar)
	req, err := http.NewRequest(http.MethodGet, sourceURL.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if received == nil {
		t.Fatal("destination request was not received")
	}
	if _, err := received.Cookie("source"); err == nil {
		t.Fatalf("cross-origin source cookie was sent: %q", received.Header.Get("Cookie"))
	}
	destinationCookie, err := received.Cookie("destination")
	if err != nil || destinationCookie.Value != "valid" {
		t.Fatalf("destination cookie = %v, %v; want destination=valid", destinationCookie, err)
	}
}

func TestRedirectCookiesPreserveDestinationScopeAcrossStatuses(t *testing.T) {
	statuses := []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	}
	for _, status := range statuses {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var received string
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received = r.Header.Get("Cookie")
				w.WriteHeader(http.StatusNoContent)
			}))
			defer target.Close()

			targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, targetURL+"/app/final", status)
			}))
			defer source.Close()

			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			sourceURL, err := url.Parse(source.URL + "/start")
			if err != nil {
				t.Fatal(err)
			}
			destinationURL, err := url.Parse(targetURL + "/app/final")
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(sourceURL, []*http.Cookie{{Name: "sid", Value: "source", Path: "/"}})
			jar.SetCookies(destinationURL, []*http.Cookie{{Name: "sid", Value: "destination", Path: "/app"}})

			c := NewClient(ClientConfig{})
			defer c.Close()
			c.SetJar(jar)
			req, err := http.NewRequest(http.MethodGet, sourceURL.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			if received != "sid=destination" {
				t.Fatalf("redirect %d Cookie = %q, want destination cookie", status, received)
			}
		})
	}
}

func TestRedirectManualCookiePreservesSameNameDestinationCookie(t *testing.T) {
	var received string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetURL+"/app/final", http.StatusFound)
	}))
	defer source.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	destinationURL, err := url.Parse(targetURL + "/app/final")
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(destinationURL, []*http.Cookie{{Name: "sid", Value: "manual", Path: "/app"}})

	c := NewClient(ClientConfig{})
	defer c.Close()
	c.SetJar(jar)
	req, err := http.NewRequest(http.MethodGet, source.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", "sid=manual")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if received != "sid=manual" {
		t.Fatalf("redirect Cookie = %q, want same-value destination cookie", received)
	}
}

func TestRedirectCookiesPreserveSameValueDestinationPathVariants(t *testing.T) {
	var received string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	targetURL := target.URL + "/app/final"
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetURL, http.StatusFound)
	}))
	defer source.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceURL, err := url.Parse(source.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	destinationURL, err := url.Parse(targetURL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(destinationURL, []*http.Cookie{
		{Name: "sid", Value: "shared", Path: "/app"},
		{Name: "sid", Value: "shared", Path: "/app/"},
	})

	c := NewClient(ClientConfig{})
	defer c.Close()
	c.SetJar(jar)
	req, err := http.NewRequest(http.MethodGet, sourceURL.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if received != "sid=shared; sid=shared" {
		t.Fatalf("redirect Cookie = %q, want both destination path variants", received)
	}
}

func TestRedirectCookiesRemoveOnlyMatchingSourcePath(t *testing.T) {
	var received string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "shared", Path: "/"})
		http.Redirect(w, r, target.URL+"/app/final", http.StatusFound)
	}))
	defer source.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	destinationURL, err := url.Parse(target.URL + "/app/final")
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(destinationURL, []*http.Cookie{{Name: "sid", Value: "shared", Path: "/app"}})

	c := NewClient(ClientConfig{})
	defer c.Close()
	c.SetJar(jar)
	req, err := http.NewRequest(http.MethodGet, source.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if received != "sid=shared" {
		t.Fatalf("redirect Cookie = %q, want destination /app cookie only", received)
	}
}

func TestRedirectRejectedResponseCookiesDoNotRemoveDestinationCookie(t *testing.T) {
	tests := []struct {
		name       string
		sourceHost string
		path       string
		reject     func(*http.Cookie) bool
	}{
		{
			name:       "invalid domain",
			sourceHost: "127.0.0.1",
			path:       "/app",
			reject: func(cookie *http.Cookie) bool {
				return cookie.Domain == "localhost"
			},
		},
		{
			name:       "invalid path",
			sourceHost: "localhost",
			path:       "/rejected",
			reject: func(cookie *http.Cookie) bool {
				return cookie.Path == "/rejected"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var received string
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received = r.Header.Get("Cookie")
				w.WriteHeader(http.StatusNoContent)
			}))
			defer target.Close()
			targetURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cookie := &http.Cookie{Name: "sid", Value: "shared", Domain: "localhost", Path: tt.path}
				http.SetCookie(w, cookie)
				http.Redirect(w, r, targetURL+tt.path+"/final", http.StatusFound)
			}))
			defer source.Close()

			base, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			destinationURL, err := url.Parse(targetURL + tt.path + "/final")
			if err != nil {
				t.Fatal(err)
			}
			base.SetCookies(destinationURL, []*http.Cookie{{Name: "sid", Value: "shared", Path: tt.path}})
			jar := &rejectingCookieJar{base: base, reject: tt.reject}

			client := NewClient(ClientConfig{})
			defer client.Close()
			client.SetJar(jar)
			sourceURL := source.URL + "/start"
			if tt.sourceHost == "localhost" {
				sourceURL = strings.Replace(sourceURL, "127.0.0.1", "localhost", 1)
			}
			req, err := http.NewRequest(http.MethodGet, sourceURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if received != "sid=shared" {
				t.Fatalf("redirect Cookie = %q, want destination cookie", received)
			}
		})
	}
}

type rejectingCookieJar struct {
	base   http.CookieJar
	reject func(*http.Cookie) bool
}

func (j *rejectingCookieJar) Cookies(u *url.URL) []*http.Cookie {
	return j.base.Cookies(u)
}

func (j *rejectingCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	accepted := make([]*http.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie != nil && j.reject(cookie) {
			continue
		}
		accepted = append(accepted, cookie)
	}
	j.base.SetCookies(u, accepted)
}

func TestRedirectSecureResponseCookieDoesNotRemoveHTTPDestinationCookie(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	t.Setenv("NO_PROXY", "*")
	t.Setenv("no_proxy", "*")

	var received string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "source", Path: "/", Secure: true})
		http.Redirect(w, r, strings.Replace(target.URL, "127.0.0.1", "cookie.example.test", 1)+"/app/final", http.StatusFound)
	}))
	defer source.Close()

	sourceURL := strings.Replace(source.URL, "127.0.0.1", "cookie.example.test", 1) + "/start"
	targetURL := strings.Replace(target.URL, "127.0.0.1", "cookie.example.test", 1) + "/app/final"
	base, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	destinationURL, err := url.Parse(targetURL)
	if err != nil {
		t.Fatal(err)
	}
	base.SetCookies(destinationURL, []*http.Cookie{{Name: "sid", Value: "destination", Path: "/app"}})

	client := NewClient(ClientConfig{
		HTTP:     core.HTTP1,
		Insecure: true,
		SystemLookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	})
	defer client.Close()
	client.SetJar(base)
	resp, err := client.HTTPClient().Get(sourceURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if received != "sid=destination" {
		t.Fatalf("redirect Cookie = %q, want HTTPS-ineligible source cookie removed without removing destination cookie", received)
	}
}

func TestCookieScopeRecordsDomainHostOnlyAndPath(t *testing.T) {
	origin := mustURL(t, "https://app.example.test/account/login")
	hostOnly := cookieScopeForSetCookie(origin, &http.Cookie{Name: "host", Value: "one"})
	if hostOnly.domain != "app.example.test" || !hostOnly.hostOnly || hostOnly.path != "/account" || !SameOrigin(hostOnly.origin, origin) {
		t.Fatalf("host-only scope = %+v", hostOnly)
	}

	domain := cookieScopeForSetCookie(origin, &http.Cookie{
		Name:   "domain",
		Value:  "two",
		Domain: ".example.test",
		Path:   "/account/private",
		Secure: true,
	})
	if domain.domain != "example.test" || domain.hostOnly || domain.path != "/account/private" || !domain.secure || !SameOrigin(domain.origin, origin) {
		t.Fatalf("domain scope = %+v", domain)
	}
}

func TestCookieScopeMatchesHostDomainAndPath(t *testing.T) {
	cases := []struct {
		name  string
		scope cookieScope
		url   string
		want  bool
	}{
		{name: "host-only exact host and path", scope: cookieScope{domain: "app.example.test", hostOnly: true, path: "/app"}, url: "https://app.example.test/app/page", want: true},
		{name: "host-only rejects subdomain", scope: cookieScope{domain: "app.example.test", hostOnly: true, path: "/"}, url: "https://child.app.example.test/", want: false},
		{name: "domain allows subdomain", scope: cookieScope{domain: "example.test", path: "/"}, url: "https://child.example.test/", want: true},
		{name: "domain rejects suffix lookalike", scope: cookieScope{domain: "example.test", path: "/"}, url: "https://notexample.test/", want: false},
		{name: "path boundary", scope: cookieScope{domain: "example.test", path: "/app"}, url: "https://example.test/application", want: false},
		{name: "nested path", scope: cookieScope{domain: "example.test", path: "/app"}, url: "https://example.test/app/page", want: true},
		{name: "secure requires HTTPS", scope: cookieScope{domain: "example.test", path: "/", secure: true}, url: "http://example.test/", want: false},
		{name: "secure allows HTTPS", scope: cookieScope{domain: "example.test", path: "/", secure: true}, url: "https://example.test/", want: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := cookieScopeMatchesRequest(tt.scope, mustURL(t, tt.url)); got != tt.want {
				t.Fatalf("cookieScopeMatchesRequest(%+v, %q) = %v, want %v", tt.scope, tt.url, got, tt.want)
			}
		})
	}
}

func TestRedirectSameOriginPreservesCustomHost(t *testing.T) {
	var gotHost string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, server.URL+"/final", http.StatusFound)
			return
		}
		gotHost = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "virtual-origin.invalid"
	resp, err := NewClient(ClientConfig{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotHost != "virtual-origin.invalid" {
		t.Fatalf("same-origin Host = %q, want virtual-origin.invalid", gotHost)
	}
}

func TestRedirectHistoryDoesNotRestoreCredentials(t *testing.T) {
	var final http.Header
	var source *httptest.Server
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, source.URL+"/final", http.StatusFound)
	}))
	defer target.Close()
	source = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, target.URL+"/middle", http.StatusFound)
			return
		}
		final = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer source.Close()

	req, err := http.NewRequest(http.MethodGet, source.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("user", "password")
	req.Header.Set("Cookie", "origin=secret")
	resp, err := NewClient(ClientConfig{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if final.Get("Authorization") != "" || final.Get("Cookie") != "" {
		t.Fatalf("credentials restored after cross-origin hop: Authorization=%q Cookie=%q", final.Get("Authorization"), final.Get("Cookie"))
	}
}

func TestRedirectsZeroReturnsOneShotRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusMovedPermanently)
	}))
	defer server.Close()
	zero := 0
	req, err := http.NewRequest(http.MethodPut, server.URL+"/start", oneShotReader{Reader: strings.NewReader("body")})
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	resp, err := NewClient(ClientConfig{Redirects: &zero}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", resp.StatusCode)
	}
}

func TestRedirectOneShotBodyReportsReplayError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodPut, server.URL+"/start", oneShotReader{Reader: strings.NewReader("body")})
	if err != nil {
		t.Fatal(err)
	}
	// Unknown-length one-shot streams must still be treated as bodies by
	// net/http's redirect policy.
	req.ContentLength = -1
	_, err = NewClient(ClientConfig{}).Do(req)
	if err == nil || !strings.Contains(err.Error(), "cannot replay request body") {
		t.Fatalf("error = %v, want replay error", err)
	}
}

type oneShotReader struct{ *strings.Reader }

func (r oneShotReader) Read(p []byte) (int, error) { return r.Reader.Read(p) }

func TestRedirectReResolvesEachDestinationWithCustomDNS(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	t.Setenv("NO_PROXY", "*")
	t.Setenv("no_proxy", "*")

	var names []string
	var namesMu sync.Mutex
	dnsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		namesMu.Lock()
		names = append(names, name)
		namesMu.Unlock()
		if r.URL.Query().Get("type") == "A" {
			_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"name":"`+name+`","type":1,"data":"127.0.0.1"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"Status":3}`)
	}))
	defer dnsServer.Close()

	var origin *httptest.Server
	origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			location := "http://localhost:" + originURLPort(origin.URL) + "/final"
			http.Redirect(w, r, location, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://bypass.example:"+originURL.Port()+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	dnsURL, err := url.Parse(dnsServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(ClientConfig{DNSServer: dnsURL})
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	seen := map[string]bool{}
	namesMu.Lock()
	defer namesMu.Unlock()
	for _, name := range names {
		seen[name] = true
	}
	if !seen["bypass.example"] || !seen["localhost"] {
		t.Fatalf("custom DNS names = %v, want both redirect destinations resolved", names)
	}
}

func originURLPort(raw string) string {
	u, _ := url.Parse(raw)
	return u.Port()
}

func TestNewClientUsesDefaultRedirectLimit(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Redirect(w, r, "/", http.StatusFound)
	}))
	defer server.Close()

	c := NewClient(ClientConfig{})

	resp, err := c.HTTPClient().Get(server.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected redirect limit error")
	}
	if !strings.Contains(err.Error(), "exceeded maximum number of redirects: 10") {
		t.Fatalf("error = %q, want default redirect limit", err)
	}
	if requests != 11 {
		t.Fatalf("requests = %d, want 11", requests)
	}
}

func TestNewClientUsesProxyFromEnvironment(t *testing.T) {
	c := NewClient(ClientConfig{})
	transport := c.HTTPClient().Transport
	if wrapped, ok := transport.(*redirectCredentialTransport); ok {
		transport = wrapped.base
	}
	wrapped, ok := transport.(*proxyTransport)
	if !ok {
		t.Fatalf("transport = %T, want *proxyTransport", c.HTTPClient().Transport)
	}
	rt, ok := wrapped.base.(*http.Transport)
	if !ok {
		t.Fatalf("proxy transport base = %T, want *http.Transport", wrapped.base)
	}
	if rt.Proxy == nil {
		t.Fatal("Proxy is nil, want http.ProxyFromEnvironment")
	}

	proxiedReq := newProxyTestRequest(t, "http://service.example/")
	got, err := rt.Proxy(proxiedReq)
	if err != nil {
		t.Fatal(err)
	}
	want := testEnvProxyURL
	if got == nil || got.String() != want {
		t.Fatalf("Proxy(%q) = %v, want %q", proxiedReq.URL, got, want)
	}

	bypassedReq := newProxyTestRequest(t, "http://bypass.example/")
	got, err = rt.Proxy(bypassedReq)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("Proxy(%q) = %v, want nil", bypassedReq.URL, got)
	}
}

func TestConnectContextUsesEarlierRequestDeadline(t *testing.T) {
	budget, err := core.NewBudget(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	ctx := WithConnectBudget(parent, budget)
	connected, stop := connectContext(ctx, time.Second, "connect")
	defer stop()
	deadline, ok := connected.Deadline()
	if !ok {
		t.Fatal("connect context has no deadline")
	}
	if remaining := time.Until(deadline); remaining > 100*time.Millisecond {
		t.Fatalf("connect deadline has %s remaining, want parent deadline", remaining)
	}
}

func TestConnectTimeoutCoversHTTPSProxyConnect(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Fatalf("proxy method = %s, want CONNECT", r.Method)
		}
		<-r.Context().Done()
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(ClientConfig{Proxy: proxyURL, ConnectTimeout: 50 * time.Millisecond})
	defer c.Close()
	req, err := c.NewRequest(context.Background(), RequestConfig{URL: mustURL(t, "https://example.com/")})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = c.Do(req)
	if err == nil {
		t.Fatal("request succeeded, want proxy CONNECT timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("proxy timeout took too long: %s", elapsed)
	}
}

func TestNewClientExplicitProxyOverridesEnvironment(t *testing.T) {
	explicitProxy, err := url.Parse("http://explicit-proxy.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(ClientConfig{Proxy: explicitProxy})
	transport := c.HTTPClient().Transport
	if wrapped, ok := transport.(*redirectCredentialTransport); ok {
		transport = wrapped.base
	}
	rt, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", c.HTTPClient().Transport)
	}

	req := newProxyTestRequest(t, "http://service.example/")
	got, err := rt.Proxy(req)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.String() != explicitProxy.String() {
		t.Fatalf("Proxy(%q) = %v, want %q", req.URL, got, explicitProxy)
	}
}

func TestCloseClosesIdleConnections(t *testing.T) {
	transport := &trackingCloseIdleTransport{}
	c := &Client{c: &http.Client{Transport: transport}}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !transport.closeIdleCalled {
		t.Fatal("CloseIdleConnections was not called")
	}
}

func TestCloseClosesTransportAfterIdleConnections(t *testing.T) {
	transport := &trackingCloseTransport{}
	c := &Client{c: &http.Client{Transport: transport}}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"close-idle", "close"}
	if !slicesEqual(transport.calls, want) {
		t.Fatalf("calls = %v, want %v", transport.calls, want)
	}
}

func TestCloseClosesResolverDOHConnections(t *testing.T) {
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		if r.URL.Query().Get("type") == "AAAA" {
			_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com","type":28,"data":"::1"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com","type":1,"data":"127.0.0.1"}]}`)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.Start()
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	res := resolver.New(resolver.Config{Server: serverURL})
	if _, err := res.LookupIPAddr(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}

	c := &Client{c: &http.Client{}, resolver: res}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Client.Close did not release the resolver's DoH connection")
	}
}

func TestNewClientCloseClosesOwnedUnifiedProxyDOHTransport(t *testing.T) {
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		if r.URL.Query().Get("type") == "AAAA" {
			_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com","type":28,"data":"::1"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com","type":1,"data":"127.0.0.1"}]}`)
	}))
	defer doh.Close()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyClosed := make(chan struct{}, 1)
	go serveOneSOCKS5Connection(proxyListener, proxyClosed)
	defer proxyListener.Close()

	dohURL, err := url.Parse(doh.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := &url.URL{Scheme: "socks5h", Host: proxyListener.Addr().String()}
	c := NewClient(ClientConfig{DNSServer: dohURL, Proxy: proxyURL, HTTP: core.HTTP1})
	if _, err := c.resolver.LookupIPAddr(context.Background(), "example.com"); err != nil {
		_ = c.Close()
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-proxyClosed:
	case <-time.After(time.Second):
		t.Fatal("Client.Close did not close the resolver-owned unified DoH transport")
	}
}

func serveOneSOCKS5Connection(listener net.Listener, closed chan<- struct{}) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer func() {
		_ = conn.Close()
		select {
		case closed <- struct{}{}:
		default:
		}
	}()

	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}

	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 5 || header[1] != 1 {
		return
	}
	var host string
	switch header[3] {
	case 1:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return
		}
		addr := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		host = string(addr)
	case 4:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, target); done <- struct{}{} }()
	<-done
	_ = conn.Close()
	_ = target.Close()
}

func TestDecodeResponseBodyClosesResponseBodyWhenDecoderConstructionFails(t *testing.T) {
	decoderErr := errors.New("bad header")
	tests := []struct {
		encoding string
	}{
		{encoding: "gzip"},
		{encoding: "zstd"},
	}

	for _, tt := range tests {
		t.Run(tt.encoding, func(t *testing.T) {
			body := &trackingReadCloser{
				Reader: bytes.NewReader([]byte("not a valid compressed body")),
			}
			resp := &http.Response{
				Body:          body,
				ContentLength: 123,
			}

			err := decodeResponseBody(resp, tt.encoding, func(io.ReadCloser) (io.ReadCloser, error) {
				return nil, decoderErr
			})
			if err == nil {
				t.Fatal("expected decoder construction error")
			}
			if !errors.Is(err, decoderErr) {
				t.Fatalf("error = %v, want wrapped %v", err, decoderErr)
			}
			if !strings.Contains(err.Error(), tt.encoding+":") {
				t.Fatalf("error = %q, want prefix containing %q", err, tt.encoding+":")
			}
			if !body.closed {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func newProxyTestRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingCloseIdleTransport struct {
	closeIdleCalled bool
}

func (t *trackingCloseIdleTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected RoundTrip")
}

func (t *trackingCloseIdleTransport) CloseIdleConnections() {
	t.closeIdleCalled = true
}

type trackingCloseTransport struct {
	calls []string
}

func (t *trackingCloseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected RoundTrip")
}

func (t *trackingCloseTransport) CloseIdleConnections() {
	t.calls = append(t.calls, "close-idle")
}

func (t *trackingCloseTransport) Close() error {
	t.calls = append(t.calls, "close")
	return nil
}

type trackingReadCloser struct {
	*bytes.Reader
	closed bool
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func newEncodingRequestedRequest(t *testing.T) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(
		context.WithValue(context.Background(), ctxEncodingRequestedKey, true),
		http.MethodGet,
		"https://example.com",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func gzipEncode(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zstdEncode(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestNewRequestCompressionModes(t *testing.T) {
	tests := []struct {
		name   string
		mode   core.CompressionMode
		accept string
	}{
		{name: "auto", mode: core.CompressionAuto, accept: "gzip, br, zstd"},
		{name: "brotli", mode: core.CompressionBrotli, accept: "br"},
		{name: "gzip", mode: core.CompressionGzip, accept: "gzip"},
		{name: "zstd", mode: core.CompressionZstd, accept: "zstd"},
		{name: "off", mode: core.CompressionOff},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{
				Compression: tt.mode,
				URL:         mustURL(t, "https://example.com"),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get("Accept-Encoding"); got != tt.accept {
				t.Fatalf("Accept-Encoding = %q, want %q", got, tt.accept)
			}
			if _, ok := responseEncodingPolicyFromRequest(req); !ok {
				t.Fatal("request has no response encoding policy")
			}
		})
	}
}

func TestNewRequestDoesNotReplaceExplicitAcceptEncoding(t *testing.T) {
	req, err := NewClient(ClientConfig{}).NewRequest(context.Background(), RequestConfig{
		Compression: core.CompressionAuto,
		Headers:     []core.KeyVal[string]{{Key: "Accept-Encoding", Val: "gzip;q=0.8"}},
		URL:         mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Accept-Encoding"); got != "gzip;q=0.8" {
		t.Fatalf("Accept-Encoding = %q, want explicit value", got)
	}
}

func TestDoOnlyDecodesAllowedCompression(t *testing.T) {
	const data = "gzip body"
	c := &Client{c: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			ContentLength: 42,
			Header:        http.Header{"Content-Encoding": {"gzip"}},
			Body:          io.NopCloser(bytes.NewReader(gzipEncode(t, []byte(data)))),
			Request:       req,
		}, nil
	})}}

	req, err := c.NewRequest(context.Background(), RequestConfig{
		Compression: core.CompressionGzip,
		URL:         mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != data {
		t.Fatalf("decoded body = %q, want %q", got, data)
	}
	if resp.ContentLength != -1 || WireContentLength(resp) != 42 {
		t.Fatalf("content lengths = decoded %d, wire %d; want -1 and 42", resp.ContentLength, WireContentLength(resp))
	}
}

func TestDoDoesNotDecodeMetadataOnlyResponses(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		statusCode int
	}{
		{name: "HEAD", method: http.MethodHead, statusCode: http.StatusOK},
		{name: "successful CONNECT", method: http.MethodConnect, statusCode: http.StatusOK},
		{name: "informational", method: http.MethodGet, statusCode: http.StatusSwitchingProtocols},
		{name: "no content", method: http.MethodGet, statusCode: http.StatusNoContent},
		{name: "reset content", method: http.MethodGet, statusCode: http.StatusResetContent},
		{name: "not modified", method: http.MethodGet, statusCode: http.StatusNotModified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			closed := false
			c := &Client{c: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode:    tt.statusCode,
					ContentLength: 128,
					Header:        http.Header{"Content-Encoding": {"gzip"}},
					Body:          &closeFlagReadCloser{Reader: bytes.NewReader(nil), closedPtr: &closed},
					Request:       req,
				}, nil
			})}}
			req, err := c.NewRequest(context.Background(), RequestConfig{
				Compression: core.CompressionGzip,
				Method:      tt.method,
				URL:         mustURL(t, "https://example.com"),
			})
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("Do returned an error for a response without a body: %v", err)
			}
			if resp.ContentLength != 128 || WireContentLength(resp) != 128 {
				t.Fatalf("content lengths = %d and %d, want encoded metadata length 128", resp.ContentLength, WireContentLength(resp))
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if !closed {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func TestDoRejectsDisallowedAndMalformedContentEncoding(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		want     string
	}{
		{name: "disallowed", encoding: "br", want: "unsupported response content encoding: br"},
		{name: "empty token", encoding: "gzip,", want: "malformed Content-Encoding header"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			closed := false
			c := &Client{c: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Encoding": {tt.encoding}},
					Body:       &closeFlagReadCloser{Reader: bytes.NewReader([]byte("body")), closedPtr: &closed},
					Request:    req,
				}, nil
			})}}
			req, err := c.NewRequest(context.Background(), RequestConfig{
				Compression: core.CompressionGzip,
				URL:         mustURL(t, "https://example.com"),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Do(req); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Do error = %v, want text %q", err, tt.want)
			}
			if !closed {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func TestDoPrefixesStreamingDecoderErrors(t *testing.T) {
	c := &Client{c: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Encoding": {"gzip"}},
			Body:       io.NopCloser(bytes.NewReader(gzipEncode(t, []byte("truncated"))[:20])),
			Request:    req,
		}, nil
	})}}
	req, err := c.NewRequest(context.Background(), RequestConfig{
		Compression: core.CompressionGzip,
		URL:         mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err == nil || !strings.Contains(err.Error(), "gzip:") {
		t.Fatalf("ReadAll error = %v, want gzip context", err)
	}
}

type closeFlagReadCloser struct {
	*bytes.Reader
	closedPtr *bool
}

func (r *closeFlagReadCloser) Close() error {
	*r.closedPtr = true
	return nil
}

func TestCompressionModeDecodersReportTruncation(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		body     func() []byte
	}{
		{
			name:     "brotli",
			encoding: "br",
			body: func() []byte {
				return []byte("\x0b\x0a\x80this is the test data\x03")
			},
		},
		{
			name:     "zstd",
			encoding: "zstd",
			body: func() []byte {
				return zstdEncode(t, []byte("truncated zstd"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.body()
			encoded = encoded[:len(encoded)-1]
			c := &Client{c: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Encoding": {tt.encoding}},
					Body:       io.NopCloser(bytes.NewReader(encoded)),
					Request:    req,
				}, nil
			})}}
			req, err := c.NewRequest(context.Background(), RequestConfig{
				Compression: core.CompressionAuto,
				URL:         mustURL(t, "https://example.com"),
			})
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if _, err := io.ReadAll(resp.Body); err == nil || !strings.Contains(err.Error(), tt.encoding+":") {
				t.Fatalf("ReadAll error = %v, want %s context", err, tt.encoding)
			}
		})
	}
}

func TestArticleDecodesResponseWhenCompressionIsOff(t *testing.T) {
	encoded := gzipEncode(t, []byte("<html><body><article><p>article</p></article></body></html>"))
	c := &Client{c: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Encoding": {"gzip"}},
			Body:       io.NopCloser(bytes.NewReader(encoded)),
			Request:    req,
		}, nil
	})}}
	req, err := c.NewRequest(context.Background(), RequestConfig{
		Article:     true,
		Compression: core.CompressionOff,
		URL:         mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "<html><body><article><p>article</p></article></body></html>" {
		t.Fatalf("article body = %q, want decoded HTML", got)
	}
}

func TestDoPreservesEncodedBytesWhenCompressionIsOff(t *testing.T) {
	encoded := gzipEncode(t, []byte("raw gzip"))
	c := &Client{c: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Encoding": {"gzip"}},
			Body:       io.NopCloser(bytes.NewReader(encoded)),
			Request:    req,
		}, nil
	})}}
	req, err := c.NewRequest(context.Background(), RequestConfig{
		Compression: core.CompressionOff,
		URL:         mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, encoded) {
		t.Fatal("compression off changed response bytes")
	}
}
