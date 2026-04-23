package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

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
	if string(got) != data {
		t.Fatalf("body = %q, want %q", got, data)
	}
}

func TestDoLeavesUnsupportedStackedContentEncodingUntouched(t *testing.T) {
	body := []byte("not decoded")
	c := &Client{
		c: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header: http.Header{
						"Content-Encoding": []string{"br, gzip"},
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingReadCloser struct {
	*bytes.Reader
	closed bool
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
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
