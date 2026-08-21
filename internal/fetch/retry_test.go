package fetch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	requestbody "github.com/ryanfowler/fetch/internal/body"
	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	imultipart "github.com/ryanfowler/fetch/internal/multipart"
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

	t.Run("retry-after is capped", func(t *testing.T) {
		retryAfter := 60 * time.Second
		delay := computeDelay(time.Second, 0, retryAfter)
		if delay != core.MaxRetryAfter {
			t.Errorf("delay = %v, want capped retry-after %v", delay, core.MaxRetryAfter)
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
	t.Run("values are capped at the shared limit", func(t *testing.T) {
		h := http.Header{"Retry-After": []string{"999999999999999999999999"}}
		got, clamped := parseRetryAfterAt(h, time.Unix(0, 0))
		if got != core.MaxRetryAfter || !clamped {
			t.Fatalf("parseRetryAfterAt = %s, clamped %v; want %s, true", got, clamped, core.MaxRetryAfter)
		}
	})

	t.Run("http dates are capped", func(t *testing.T) {
		now := time.Unix(100, 0)
		h := http.Header{"Retry-After": []string{now.Add(time.Minute).UTC().Format(http.TimeFormat)}}
		got, clamped := parseRetryAfterAt(h, now)
		if got != core.MaxRetryAfter || !clamped {
			t.Fatalf("parseRetryAfterAt = %s, clamped %v; want %s, true", got, clamped, core.MaxRetryAfter)
		}
	})

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

func TestSchemelessPlaintextHint(t *testing.T) {
	u, err := url.Parse("https://example.com:8080/path?debug=true")
	if err != nil {
		t.Fatal(err)
	}
	r := &Request{URL: u, SchemelessURL: true}
	connectErr := &url.Error{Op: "Get", URL: u.String(), Err: tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}}
	if got := schemelessPlaintextHint(r, connectErr); got != "http://example.com:8080/path?debug=true" {
		t.Fatalf("hint = %q", got)
	}

	r.SchemelessURL = false
	if got := schemelessPlaintextHint(r, connectErr); got != "" {
		t.Fatalf("explicit URL hint = %q, want empty", got)
	}
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

	t.Run("503 honors capped Retry-After", func(t *testing.T) {
		resp := &http.Response{StatusCode: 503, Header: http.Header{"Retry-After": []string{"60"}}}
		ok, delay := shouldRetry(resp, nil)
		if !ok || delay != core.MaxRetryAfter {
			t.Fatalf("shouldRetry = %v, %s; want true, %s", ok, delay, core.MaxRetryAfter)
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

func TestDelayFitsPreservesEarlierCallerDeadline(t *testing.T) {
	budget, err := core.NewBudget(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := delayFits(ctx, budget, time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("delayFits error = %v, want caller deadline", err)
	}
}

func TestRetryBudgetCoversDelay(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	r := &Request{
		Discard:       true,
		Retry:         1,
		RetryDelay:    time.Second,
		Timeout:       50 * time.Millisecond,
		URL:           mustParseURL(server.URL),
		PrinterHandle: core.NewHandle(core.ColorOff),
	}
	c := client.NewClient(client.ClientConfig{})
	defer c.Close()
	req, err := c.NewRequest(context.Background(), client.RequestConfig{URL: r.URL})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = retryableRequest(context.Background(), r, c, req)
	if err == nil {
		t.Fatal("retryableRequest succeeded, want shared timeout")
	}
	var timeout core.TimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("error = %v, want timeout", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want one attempt", requests)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("shared timeout took too long: %s", elapsed)
	}
}

func TestRetryDrainHasBoundedTime(t *testing.T) {
	body := newBlockingBody()
	start := time.Now()
	if err := drainResponseBody(context.Background(), body); err != nil {
		t.Fatalf("drainResponseBody: %v", err)
	}
	if elapsed := time.Since(start); elapsed < maxRetryDrainTime/2 || elapsed > time.Second {
		t.Fatalf("drain elapsed = %s, want approximately %s", elapsed, maxRetryDrainTime)
	}
	select {
	case <-body.closed:
	default:
		t.Fatal("drain did not close the response body")
	}
}

func TestRetryBudgetCoversResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("x"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	defer server.Close()

	r := &Request{
		Discard:       true,
		Timeout:       50 * time.Millisecond,
		PrinterHandle: core.NewHandle(core.ColorOff),
	}
	c := client.NewClient(client.ClientConfig{})
	defer c.Close()
	req, err := c.NewRequest(context.Background(), client.RequestConfig{URL: mustParseURL(server.URL)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = retryableRequest(context.Background(), r, c, req)
	var timeout core.TimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("error = %v, want response timeout", err)
	}
}

func TestRetryUsesCallerCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-started:
		default:
			close(started)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Request{Retry: 1, RetryDelay: time.Second, PrinterHandle: core.NewHandle(core.ColorOff)}
	c := client.NewClient(client.ClientConfig{})
	defer c.Close()
	req, err := c.NewRequest(context.Background(), client.RequestConfig{URL: mustParseURL(server.URL)})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := retryableRequest(ctx, r, c, req)
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not stop retry")
	}
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

func TestDoOnceDigestAfterRedirectUsesChallengedRequest(t *testing.T) {
	var startHits, protectedHits int
	var protectedMethod, protectedBody, digestURI string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			startHits++
			http.Redirect(w, r, server.URL+"/protected?token=1", http.StatusSeeOther)
		case "/protected":
			protectedHits++
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			protectedMethod = r.Method
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read protected body: %v", err)
			}
			protectedBody = string(body)
			digestURI = digestAuthParam(auth, "uri")
			if digestURI != "/protected?token=1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/start", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("payload")), nil
	}
	replayer, err := newReplayableBody(req)
	if err != nil {
		t.Fatalf("new replayable body: %v", err)
	}
	body, err := replayer.reset()
	if err != nil {
		t.Fatalf("reset body: %v", err)
	}
	req.Body = body

	resp, err := doOnce(
		&Request{Digest: &core.KeyVal[string]{Key: "user", Val: "pass"}},
		client.NewClient(client.ClientConfig{}),
		req,
		replayer,
	)
	if err != nil {
		t.Fatalf("doOnce: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if startHits != 1 {
		t.Fatalf("start hits = %d, want 1", startHits)
	}
	if protectedHits != 2 {
		t.Fatalf("protected hits = %d, want 2", protectedHits)
	}
	if protectedMethod != http.MethodGet {
		t.Fatalf("protected retry method = %s, want GET", protectedMethod)
	}
	if protectedBody != "" {
		t.Fatalf("protected retry body = %q, want empty", protectedBody)
	}
	if digestURI != "/protected?token=1" {
		t.Fatalf("digest uri = %q, want /protected?token=1", digestURI)
	}
}

func TestRetryableRequestSetsGetBodyForMultipartRedirect(t *testing.T) {
	var startHits, finalHits int
	var finalMethod, finalBody, finalContentType string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			startHits++
			http.Redirect(w, r, server.URL+"/final", http.StatusTemporaryRedirect)
		case "/final":
			finalHits++
			finalMethod = r.Method
			finalContentType = r.Header.Get("Content-Type")
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read final body: %v", err)
			}
			finalBody = string(body)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	mp := imultipart.NewMultipart([]core.KeyVal[string]{
		{Key: "field", Val: "value"},
	})
	body, err := mp.Open()
	if err != nil {
		t.Fatalf("open multipart: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+"/start", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", mp.ContentType())
	req.GetBody = mp.Open

	code, err := retryableRequest(
		context.Background(),
		&Request{
			Digest:        &core.KeyVal[string]{Key: "user", Val: "pass"},
			Discard:       true,
			PrinterHandle: core.NewHandle(core.ColorOff),
		},
		client.NewClient(client.ClientConfig{}),
		req,
	)
	if err != nil {
		t.Fatalf("retryableRequest: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if startHits != 1 {
		t.Fatalf("start hits = %d, want 1", startHits)
	}
	if finalHits != 1 {
		t.Fatalf("final hits = %d, want 1", finalHits)
	}
	if finalMethod != http.MethodPost {
		t.Fatalf("final method = %s, want POST", finalMethod)
	}
	if !strings.HasPrefix(finalContentType, "multipart/form-data; boundary=") {
		t.Fatalf("final content-type = %q, want multipart/form-data", finalContentType)
	}
	if !strings.Contains(finalBody, `name="field"`) || !strings.Contains(finalBody, "value") {
		t.Fatalf("final body did not contain multipart field: %q", finalBody)
	}
}

func digestAuthParam(auth, key string) string {
	auth, ok := strings.CutPrefix(auth, "Digest ")
	if !ok {
		return ""
	}
	for part := range strings.SplitSeq(auth, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || k != key {
			continue
		}
		return strings.Trim(v, `"`)
	}
	return ""
}

func TestReplayableBody(t *testing.T) {
	t.Run("one-shot source is rejected before replay", func(t *testing.T) {
		req := &http.Request{Body: io.NopCloser(strings.NewReader("stdin"))}
		source := requestbody.NewReader(req.Body, -1, "")
		requestbody.Attach(req, source)

		_, err := newReplayableBody(req)
		if !errors.Is(err, requestbody.ErrNotReplayable) {
			t.Fatalf("newReplayableBody error = %v, want ErrNotReplayable", err)
		}
	})

	t.Run("getbody body", func(t *testing.T) {
		req := &http.Request{
			Body: io.NopCloser(bytes.NewReader([]byte("hello"))),
			GetBody: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("hello"))), nil
			},
		}
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
			if string(data) != "hello" {
				t.Errorf("expected 'hello', got '%s'", data)
			}
			rc.Close()
		}
	})

	t.Run("closable seekable body", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "body-*")
		if err != nil {
			t.Fatalf("create temp file: %v", err)
		}
		if _, err := f.WriteString("hello"); err != nil {
			t.Fatalf("write temp file: %v", err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			t.Fatalf("seek temp file: %v", err)
		}

		req := &http.Request{Body: f}
		rb, err := newReplayableBody(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer rb.close()
		if _, err := f.Read(make([]byte, 1)); !isClosedFileErr(err) {
			t.Fatalf("expected original file to be closed, got %v", err)
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
			if err := rc.Close(); err != nil {
				t.Fatalf("close error: %v", err)
			}
		}
	})

	t.Run("unknown streamed body is rejected without buffering", func(t *testing.T) {
		body := &streamingReadCloser{remaining: 8 << 20, fill: 'x'}
		req := &http.Request{Body: body}
		_, err := newReplayableBody(req)
		if !errors.Is(err, requestbody.ErrNotReplayable) {
			t.Fatalf("newReplayableBody error = %v, want ErrNotReplayable", err)
		}
		if body.reads != 0 {
			t.Fatalf("body reads = %d, want 0", body.reads)
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

func TestFindDigestChallenge(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   string
	}{
		{
			name:   "single digest header",
			header: http.Header{"Www-Authenticate": []string{`Digest realm="test", nonce="abc123"`}},
			want:   `Digest realm="test", nonce="abc123"`,
		},
		{
			name:   "single basic header",
			header: http.Header{"Www-Authenticate": []string{`Basic realm="test"`}},
			want:   "",
		},
		{
			name:   "combined digest second",
			header: http.Header{"Www-Authenticate": []string{`Basic realm="x", Digest realm="y", nonce="abc123"`}},
			want:   `Digest realm="y", nonce="abc123"`,
		},
		{
			name:   "combined digest second no space after comma",
			header: http.Header{"Www-Authenticate": []string{`Basic realm="x",Digest realm="y",nonce="abc123"`}},
			want:   `Digest realm="y",nonce="abc123"`,
		},
		{
			name:   "combined digest first",
			header: http.Header{"Www-Authenticate": []string{`Digest realm="y", nonce="abc123", Basic realm="x"`}},
			want:   `Digest realm="y", nonce="abc123"`,
		},
		{
			name:   "combined multiple trailing",
			header: http.Header{"Www-Authenticate": []string{`Basic realm="x", Digest realm="y", nonce="abc123", Bearer token="z"`}},
			want:   `Digest realm="y", nonce="abc123"`,
		},
		{
			name:   "multiple headers",
			header: http.Header{"Www-Authenticate": []string{`Basic realm="x"`, `Digest realm="y", nonce="abc123"`}},
			want:   `Digest realm="y", nonce="abc123"`,
		},
		{
			name:   "digest inside quoted string",
			header: http.Header{"Www-Authenticate": []string{`Basic realm="My Digest", Digest realm="y", nonce="abc123"`}},
			want:   `Digest realm="y", nonce="abc123"`,
		},
		{
			name:   "escaped quotes",
			header: http.Header{"Www-Authenticate": []string{`Basic realm="My \"Digest\"", Digest realm="y", nonce="abc123"`}},
			want:   `Digest realm="y", nonce="abc123"`,
		},
		{
			name:   "space separated no comma",
			header: http.Header{"Www-Authenticate": []string{`Basic realm="x" Digest realm="y" nonce="abc123"`}},
			want:   `Digest realm="y" nonce="abc123"`,
		},
		{
			name:   "no digest",
			header: http.Header{"Www-Authenticate": []string{`Basic realm="x", Bearer token="z"`}},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findDigestChallenge(tt.header)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func isClosedFileErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "file already closed")
}

type blockingBody struct {
	closed chan struct{}
}

func newBlockingBody() *blockingBody {
	return &blockingBody{closed: make(chan struct{})}
}

func (b *blockingBody) Read([]byte) (int, error) {
	<-b.closed
	return 0, errors.New("body closed")
}

func (b *blockingBody) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

type streamingReadCloser struct {
	remaining int64
	fill      byte
	closed    bool
	reads     int
}

func (r *streamingReadCloser) Read(p []byte) (int, error) {
	r.reads++
	if r.closed {
		return 0, os.ErrClosed
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = r.fill
	}
	r.remaining -= int64(len(p))
	return len(p), nil
}

func (r *streamingReadCloser) Close() error {
	r.closed = true
	return nil
}
