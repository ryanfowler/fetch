package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestDoRejectsExcessiveContentEncodingChain(t *testing.T) {
	tests := []struct {
		name   string
		values []string
	}{
		{name: "brotli amplification", values: []string{strings.TrimSuffix(strings.Repeat("br,", 512), ",")}},
		{name: "one over limit", values: []string{strings.TrimSuffix(strings.Repeat("gzip,", core.MaxResponseEncodingLayers+1), ",")}},
		{name: "multiple headers", values: []string{"br", strings.TrimSuffix(strings.Repeat("gzip,", core.MaxResponseEncodingLayers), ",")}},
		{name: "identity counts", values: []string{strings.Repeat("identity,", core.MaxResponseEncodingLayers) + "gzip"}},
		{name: "aws-chunked counts", values: []string{strings.Repeat("aws-chunked,", core.MaxResponseEncodingLayers) + "gzip"}},
	}
	for _, legacy := range []bool{false, true} {
		mode := "policy"
		if legacy {
			mode = "legacy"
		}
		for _, tt := range tests {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				body := &trackingReadCloser{Reader: bytes.NewReader([]byte("x"))}
				c := encodingChainTestClient(body, tt.values)
				req := encodingChainTestRequest(t, c, legacy)
				resp, err := c.Do(req)
				if resp != nil {
					defer resp.Body.Close()
				}
				if !errors.Is(err, core.ErrLimitExceeded) || resp != nil {
					t.Fatalf("Do: response present = %t, error = %v; want nil response and resource limit error", resp != nil, err)
				}
				if !strings.Contains(err.Error(), fmt.Sprintf("%d-entry limit", core.MaxResponseEncodingLayers)) || !strings.Contains(err.Error(), "Content-Encoding") {
					t.Fatalf("limit error does not identify the header and limit: %v", err)
				}
				if !body.closed {
					t.Fatal("rejected response body was not closed")
				}
				if body.Len() != 1 {
					t.Fatal("response body was read before rejecting the encoding chain")
				}
			})
		}
	}
}

func TestDoDecodesContentEncodingChainAtLimit(t *testing.T) {
	const data = "response at the encoding chain limit"
	encoded := []byte(data)
	for range core.MaxResponseEncodingLayers {
		encoded = gzipEncode(t, encoded)
	}
	for _, legacy := range []bool{false, true} {
		mode := "policy"
		if legacy {
			mode = "legacy"
		}
		t.Run(mode, func(t *testing.T) {
			body := &trackingReadCloser{Reader: bytes.NewReader(encoded)}
			c := encodingChainTestClient(body, []string{"gzip", strings.TrimSuffix(strings.Repeat("gzip,", core.MaxResponseEncodingLayers-1), ",")})
			resp, err := c.Do(encodingChainTestRequest(t, c, legacy))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			decoded, err := io.ReadAll(resp.Body)
			if err != nil || string(decoded) != data {
				t.Fatalf("decoded body = %q, error = %v; want %q", decoded, err, data)
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if !body.closed {
				t.Fatal("closing decoder chain did not close the underlying body")
			}
		})
	}
}

func TestDoSkipsContentEncodingLimitWithoutDecoding(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		compression core.CompressionMode
	}{
		{name: "compression off", method: http.MethodGet, compression: core.CompressionOff},
		{name: "metadata only", method: http.MethodHead, compression: core.CompressionAuto},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &trackingReadCloser{Reader: bytes.NewReader([]byte("x"))}
			c := encodingChainTestClient(body, []string{strings.TrimSuffix(strings.Repeat("br,", 512), ",")})
			req, err := c.NewRequest(context.Background(), RequestConfig{
				Compression: tt.compression,
				Method:      tt.method,
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
			if resp.Body != body || body.closed || body.Len() != 1 {
				t.Fatal("response body changed despite decoding being disabled")
			}
		})
	}
}

func encodingChainTestClient(body io.ReadCloser, values []string) *Client {
	return &Client{c: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Encoding": values},
			Body:       body,
			Request:    req,
		}, nil
	})}}
}

func encodingChainTestRequest(t *testing.T, c *Client, legacy bool) *http.Request {
	t.Helper()
	if legacy {
		return newEncodingRequestedRequest(t)
	}
	req, err := c.NewRequest(context.Background(), RequestConfig{
		Compression: core.CompressionAuto,
		URL:         mustURL(t, "https://example.com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return req
}
