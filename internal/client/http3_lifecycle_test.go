package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestRoundTripHTTP3ReturnsRequestBodyReadError(t *testing.T) {
	want := errors.New("upload failed")
	transport := h3RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		_, err := io.ReadAll(req.Body)
		if !errors.Is(err, want) {
			t.Fatalf("transport body error = %v, want %v", err, want)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("unexpected response")),
			Request:    req,
		}, nil
	})
	body := &failingReadCloser{err: want}
	req, err := http.NewRequest(http.MethodPost, "https://example.com/", body)
	if err != nil {
		t.Fatal(err)
	}

	_, err = roundTripHTTP3(transport, req)
	if !errors.Is(err, want) {
		t.Fatalf("roundTripHTTP3 error = %v, want %v", err, want)
	}
	if !strings.Contains(err.Error(), "HTTP/3 request body") {
		t.Fatalf("error = %q, want HTTP/3 body context", err)
	}
}

func TestRoundTripHTTP3PreservesResponseEOF(t *testing.T) {
	transport := h3RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("response")), Request: req}, nil
	})
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := roundTripHTTP3(transport, req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != "response" {
		t.Fatalf("response = %q", got)
	}
}

func TestRoundTripHTTP3CancelsResponseBodyOnContextDeadline(t *testing.T) {
	body := newBlockingReadCloser()
	transport := h3RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body, Request: req}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := roundTripHTTP3(transport, req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	readDone := make(chan error, 1)
	go func() {
		_, readErr := resp.Body.Read(make([]byte, 1))
		readDone <- readErr
	}()
	select {
	case readErr := <-readDone:
		if !errors.Is(readErr, context.DeadlineExceeded) {
			t.Fatalf("body read error = %v, want deadline exceeded", readErr)
		}
	case <-time.After(time.Second):
		t.Fatal("response body did not stop after request deadline")
	}
	if !body.wasClosed() {
		t.Fatal("response body was not closed after request deadline")
	}
}

func TestRoundTripHTTP3CloseCancelsUnreadResponse(t *testing.T) {
	body := newBlockingReadCloser()
	transport := h3RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body, Request: req}, nil
	})
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := roundTripHTTP3(transport, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !body.wasClosed() {
		t.Fatal("closing response did not close the HTTP/3 stream body")
	}
}

func TestClassifyHTTP3Error(t *testing.T) {
	settings := &http3.Error{Remote: true, ErrorCode: http3.ErrCodeSettingsError}
	got := classifyHTTP3Error(settings, false)
	var h3Err *HTTP3Error
	if !errors.As(got, &h3Err) || h3Err.Kind != HTTP3SettingsFailure {
		t.Fatalf("settings error = %v, kind = %v", got, h3Err)
	}

	stream := &http3.Error{Remote: true, ErrorCode: http3.ErrCodeRequestCanceled}
	got = classifyHTTP3Error(stream, false)
	if !errors.As(got, &h3Err) || h3Err.Kind != HTTP3StreamFailure {
		t.Fatalf("stream error = %v, kind = %v", got, h3Err)
	}

	reset := &quic.StreamError{Remote: true, ErrorCode: quic.StreamErrorCode(http3.ErrCodeRequestCanceled)}
	got = classifyHTTP3Error(reset, true)
	if !errors.As(got, &h3Err) || h3Err.Kind != HTTP3StreamFailure {
		t.Fatalf("stream reset = %v, kind = %v", got, h3Err)
	}

	status := HTTP3StatusError(&http.Response{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway"})
	if !errors.As(status, &h3Err) || h3Err.Kind != HTTP3RemoteStatusFailure {
		t.Fatalf("status error = %v, kind = %v", status, h3Err)
	}
}

type h3RoundTripperFunc func(*http.Request) (*http.Response, error)

func (f h3RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type failingReadCloser struct {
	err    error
	done   bool
	closed bool
}

func (r *failingReadCloser) Read([]byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return 0, r.err
}

func (r *failingReadCloser) Close() error {
	r.closed = true
	return nil
}

type blockingReadCloser struct {
	mu     sync.Mutex
	closed bool
	done   chan struct{}
	once   sync.Once
}

func newBlockingReadCloser() *blockingReadCloser {
	return &blockingReadCloser{done: make(chan struct{})}
}

func (r *blockingReadCloser) Read([]byte) (int, error) {
	<-r.done
	return 0, errors.New("stream closed")
}

func (r *blockingReadCloser) Close() error {
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		close(r.done)
	})
	return nil
}

func (r *blockingReadCloser) wasClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

var _ io.ReadCloser = (*failingReadCloser)(nil)
var _ io.ReadCloser = (*blockingReadCloser)(nil)
