package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	imultipart "github.com/ryanfowler/fetch/internal/multipart"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

const (
	testEnvProxyHost = "proxy.example:8080"
	testEnvProxyURL  = "http://" + testEnvProxyHost
)

func TestMain(m *testing.M) {
	os.Setenv("HTTP_PROXY", testEnvProxyURL)
	os.Setenv("NO_PROXY", "bypass.example")
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
	// The google/brotli module only provides a decoder. Keep the encoded
	// fixture constant so this test does not need a second Brotli dependency.
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
	dnsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		names = append(names, name)
		if r.URL.Query().Get("type") == "A" {
			_, _ = io.WriteString(w, `{"Status":0,"Answer":[{"type":1,"data":"127.0.0.1"}]}`)
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
	rt, ok := c.HTTPClient().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", c.HTTPClient().Transport)
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
	rt, ok := c.HTTPClient().Transport.(*http.Transport)
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
