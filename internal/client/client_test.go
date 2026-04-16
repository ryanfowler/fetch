package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
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
