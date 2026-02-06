package fetch

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestComputeDelay(t *testing.T) {
	t.Run("exponential growth", func(t *testing.T) {
		// With no jitter influence check, just verify growth trend.
		// Run multiple times to account for jitter and verify bounds.
		for attempt := range 5 {
			delay := computeDelay(time.Second, attempt, 0)
			// Base delay is 1s * 2^attempt, ±25% jitter.
			base := min(time.Second*time.Duration(1<<attempt), 30*time.Second)
			minDelay := time.Duration(float64(base) * 0.75)
			maxDelay := time.Duration(float64(base) * 1.25)
			if delay < minDelay || delay > maxDelay {
				t.Errorf("attempt %d: delay %v out of bounds [%v, %v]", attempt, delay, minDelay, maxDelay)
			}
		}
	})

	t.Run("max cap at 30s", func(t *testing.T) {
		delay := computeDelay(time.Second, 10, 0)
		maxWithJitter := time.Duration(float64(30*time.Second) * 1.25)
		if delay > maxWithJitter {
			t.Errorf("delay %v exceeds max cap with jitter %v", delay, maxWithJitter)
		}
	})

	t.Run("retry-after override", func(t *testing.T) {
		retryAfter := 60 * time.Second
		delay := computeDelay(time.Second, 0, retryAfter)
		if delay < retryAfter {
			t.Errorf("delay %v should be at least retry-after %v", delay, retryAfter)
		}
	})

	t.Run("zero initial delay uses 1s default", func(t *testing.T) {
		delay := computeDelay(0, 0, 0)
		// Should behave like 1s initial ±25% jitter.
		if delay < 750*time.Millisecond || delay > 1250*time.Millisecond {
			t.Errorf("delay %v out of expected range for 1s default", delay)
		}
	})
}

func TestFormatDelay(t *testing.T) {
	t.Run("sub-millisecond", func(t *testing.T) {
		got := formatDelay(500 * time.Microsecond)
		if got != "0s" {
			t.Errorf("expected '0s', got '%s'", got)
		}
	})

	t.Run("milliseconds", func(t *testing.T) {
		got := formatDelay(250 * time.Millisecond)
		if got != "250ms" {
			t.Errorf("expected '250ms', got '%s'", got)
		}
	})

	t.Run("seconds", func(t *testing.T) {
		got := formatDelay(2500 * time.Millisecond)
		if got != "2.5s" {
			t.Errorf("expected '2.5s', got '%s'", got)
		}
	})
}

func TestParseRetryAfter(t *testing.T) {
	t.Run("integer seconds", func(t *testing.T) {
		h := http.Header{}
		h.Set("Retry-After", "5")
		d := parseRetryAfter(h)
		if d != 5*time.Second {
			t.Errorf("expected 5s, got %v", d)
		}
	})

	t.Run("zero seconds", func(t *testing.T) {
		h := http.Header{}
		h.Set("Retry-After", "0")
		d := parseRetryAfter(h)
		if d != 0 {
			t.Errorf("expected 0, got %v", d)
		}
	})

	t.Run("negative integer", func(t *testing.T) {
		h := http.Header{}
		h.Set("Retry-After", "-5")
		d := parseRetryAfter(h)
		if d != 0 {
			t.Errorf("expected 0, got %v", d)
		}
	})

	t.Run("empty header", func(t *testing.T) {
		h := http.Header{}
		d := parseRetryAfter(h)
		if d != 0 {
			t.Errorf("expected 0, got %v", d)
		}
	})

	t.Run("invalid value", func(t *testing.T) {
		h := http.Header{}
		h.Set("Retry-After", "not-a-number")
		d := parseRetryAfter(h)
		if d != 0 {
			t.Errorf("expected 0, got %v", d)
		}
	})

	t.Run("http-date format", func(t *testing.T) {
		future := time.Now().Add(10 * time.Second)
		h := http.Header{}
		h.Set("Retry-After", future.UTC().Format(http.TimeFormat))
		d := parseRetryAfter(h)
		// Should be approximately 10 seconds.
		if d < 8*time.Second || d > 12*time.Second {
			t.Errorf("expected ~10s, got %v", d)
		}
	})
}

func TestShouldRetry(t *testing.T) {
	t.Run("429 is retryable", func(t *testing.T) {
		resp := &http.Response{StatusCode: 429, Header: http.Header{}}
		ok, _ := shouldRetry(resp, nil)
		if !ok {
			t.Error("expected 429 to be retryable")
		}
	})

	t.Run("502 is retryable", func(t *testing.T) {
		resp := &http.Response{StatusCode: 502}
		ok, _ := shouldRetry(resp, nil)
		if !ok {
			t.Error("expected 502 to be retryable")
		}
	})

	t.Run("503 is retryable", func(t *testing.T) {
		resp := &http.Response{StatusCode: 503}
		ok, _ := shouldRetry(resp, nil)
		if !ok {
			t.Error("expected 503 to be retryable")
		}
	})

	t.Run("504 is retryable", func(t *testing.T) {
		resp := &http.Response{StatusCode: 504}
		ok, _ := shouldRetry(resp, nil)
		if !ok {
			t.Error("expected 504 to be retryable")
		}
	})

	t.Run("200 is not retryable", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200}
		ok, _ := shouldRetry(resp, nil)
		if ok {
			t.Error("expected 200 to not be retryable")
		}
	})

	t.Run("400 is not retryable", func(t *testing.T) {
		resp := &http.Response{StatusCode: 400}
		ok, _ := shouldRetry(resp, nil)
		if ok {
			t.Error("expected 400 to not be retryable")
		}
	})

	t.Run("404 is not retryable", func(t *testing.T) {
		resp := &http.Response{StatusCode: 404}
		ok, _ := shouldRetry(resp, nil)
		if ok {
			t.Error("expected 404 to not be retryable")
		}
	})

	t.Run("connection error is retryable", func(t *testing.T) {
		err := &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host"}}
		ok, _ := shouldRetry(nil, err)
		if !ok {
			t.Error("expected connection error to be retryable")
		}
	})

	t.Run("context canceled is not retryable", func(t *testing.T) {
		ok, _ := shouldRetry(nil, context.Canceled)
		if ok {
			t.Error("expected context.Canceled to not be retryable")
		}
	})

	t.Run("url error wrapping net error is retryable", func(t *testing.T) {
		err := &url.Error{Op: "Get", URL: "http://example.com", Err: &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host"}}}
		ok, _ := shouldRetry(nil, err)
		if !ok {
			t.Error("expected url.Error wrapping net error to be retryable")
		}
	})

	t.Run("url error wrapping non-retryable error is not retryable", func(t *testing.T) {
		err := &url.Error{Op: "Get", URL: "http://example.com", Err: fmt.Errorf("exceeded maximum number of redirects: 1")}
		ok, _ := shouldRetry(nil, err)
		if ok {
			t.Error("expected url.Error wrapping redirect limit error to not be retryable")
		}
	})
}

func TestIsRetryableError(t *testing.T) {
	t.Run("TLS cert error wrapped in url.Error is not retryable", func(t *testing.T) {
		err := &url.Error{
			Op:  "Get",
			URL: "https://example.com",
			Err: x509.UnknownAuthorityError{},
		}
		if isRetryableError(err) {
			t.Error("expected x509.UnknownAuthorityError wrapped in url.Error to not be retryable")
		}
	})

	t.Run("context.DeadlineExceeded is retryable", func(t *testing.T) {
		if !isRetryableError(context.DeadlineExceeded) {
			t.Error("expected context.DeadlineExceeded to be retryable")
		}
	})

	t.Run("ErrRequestTimedOut is retryable", func(t *testing.T) {
		err := core.ErrRequestTimedOut{Timeout: 500 * time.Millisecond}
		if !isRetryableError(err) {
			t.Error("expected ErrRequestTimedOut to be retryable")
		}
	})

	t.Run("ErrRequestTimedOut wrapped in url.Error is retryable", func(t *testing.T) {
		err := &url.Error{
			Op:  "Get",
			URL: "http://example.com",
			Err: core.ErrRequestTimedOut{Timeout: 500 * time.Millisecond},
		}
		if !isRetryableError(err) {
			t.Error("expected ErrRequestTimedOut wrapped in url.Error to be retryable")
		}
	})
}

func TestSleepWithContext(t *testing.T) {
	t.Run("normal sleep", func(t *testing.T) {
		ctx := context.Background()
		start := time.Now()
		err := sleepWithContext(ctx, 50*time.Millisecond)
		elapsed := time.Since(start)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if elapsed < 40*time.Millisecond {
			t.Errorf("slept too short: %v", elapsed)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := sleepWithContext(ctx, time.Second)
		if err == nil {
			t.Error("expected error from cancelled context")
		}
	})
}

func TestReplayableBody(t *testing.T) {
	t.Run("seekable body", func(t *testing.T) {
		body := &readSeekCloser{Reader: bytes.NewReader([]byte("hello"))}
		req := &http.Request{Body: body}
		rb, err := newReplayableBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rb.seeker == nil {
			t.Fatal("expected seeker path to be used for ReadSeeker body")
		}

		for range 3 {
			rc, err := rb.reset()
			if err != nil {
				t.Fatalf("reset error: %v", err)
			}
			data, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			if string(data) != "hello" {
				t.Errorf("expected 'hello', got '%s'", data)
			}
		}
	})

	t.Run("buffered body", func(t *testing.T) {
		body := bytes.NewReader([]byte("hello"))
		req := &http.Request{Body: io.NopCloser(body)}
		// bytes.Reader wrapped in NopCloser is not a ReadSeeker,
		// so it will be read into memory.
		rb, err := newReplayableBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rb.seeker != nil {
			t.Fatal("expected buffered path to be used for non-ReadSeeker body")
		}

		for range 3 {
			rc, err := rb.reset()
			if err != nil {
				t.Fatalf("reset error: %v", err)
			}
			data, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			if string(data) != "hello" {
				t.Errorf("expected 'hello', got '%s'", data)
			}
		}
	})

	t.Run("non-seekable body", func(t *testing.T) {
		body := io.NopCloser(strings.NewReader("world"))
		req := &http.Request{Body: body}
		rb, err := newReplayableBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for range 3 {
			rc, err := rb.reset()
			if err != nil {
				t.Fatalf("reset error: %v", err)
			}
			data, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			if string(data) != "world" {
				t.Errorf("expected 'world', got '%s'", data)
			}
		}
	})

	t.Run("nil body", func(t *testing.T) {
		req := &http.Request{}
		rb, err := newReplayableBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rb != nil {
			t.Error("expected nil replayableBody for nil body")
		}
	})

	t.Run("no body", func(t *testing.T) {
		req := &http.Request{Body: http.NoBody}
		rb, err := newReplayableBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rb != nil {
			t.Error("expected nil replayableBody for NoBody")
		}
	})
}

// readSeekCloser wraps a bytes.Reader to implement io.ReadSeeker and io.ReadCloser.
type readSeekCloser struct {
	*bytes.Reader
}

func (r *readSeekCloser) Close() error { return nil }
