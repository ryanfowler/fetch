package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time              { return c.now }
func (c *fakeClock) advance(delta time.Duration) { c.now = c.now.Add(delta) }

func testAllowanceContext(limit time.Duration, clock *fakeClock) context.Context {
	ctx := WithConnectTimeout(context.Background(), limit)
	ctx.Value(ctxConnectAllowanceKey).(*connectAllowance).now = clock.Now
	return ctx
}

func remainingAt(t *testing.T, ctx context.Context, now time.Time) time.Duration {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("connect context has no deadline")
	}
	return deadline.Sub(now)
}

func TestConnectAllowanceIgnoresTimeBetweenAttempts(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	ctx := testAllowanceContext(time.Second, clock)

	first, end := connectContext(ctx, 0, "connect")
	if got := remainingAt(t, first, clock.now); got != time.Second {
		t.Fatalf("first attempt has %v, want 1s", got)
	}
	clock.advance(300 * time.Millisecond)
	end()

	// Waiting for a response, or a retry delay, does not use the allowance.
	clock.advance(10 * time.Second)
	second, end := connectContext(ctx, 0, "connect")
	defer end()
	if got := remainingAt(t, second, clock.now); got != 700*time.Millisecond {
		t.Fatalf("second attempt has %v, want 700ms", got)
	}
}

func TestConnectAllowanceCountsOverlappingAttemptsOnce(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	ctx := testAllowanceContext(time.Second, clock)

	_, endOuter := connectContext(ctx, 0, "proxy connect")
	clock.advance(100 * time.Millisecond)
	inner, endInner := connectContext(ctx, 0, "TCP connect")
	if got := remainingAt(t, inner, clock.now); got != 900*time.Millisecond {
		t.Fatalf("nested attempt has %v, want 900ms", got)
	}
	clock.advance(100 * time.Millisecond)
	endInner()
	endInner() // A second call must not count the attempt twice.
	clock.advance(100 * time.Millisecond)
	endOuter()

	clock.advance(time.Minute)
	next, end := connectContext(ctx, 0, "connect")
	defer end()
	if got := remainingAt(t, next, clock.now); got != 700*time.Millisecond {
		t.Fatalf("next attempt has %v, want 700ms", got)
	}
}

func TestConnectAllowanceReportsConnectionTimeout(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	ctx := testAllowanceContext(time.Second, clock)
	_, end := connectContext(ctx, 0, "connect")
	clock.advance(2 * time.Second)
	end()

	expired, end := connectContext(ctx, 0, "TLS connect")
	defer end()
	<-expired.Done()
	var timeout core.TimeoutError
	if !errors.As(context.Cause(expired), &timeout) || !timeout.Connection || timeout.Duration != time.Second {
		t.Fatalf("cause = %v, want 1s connection timeout", context.Cause(expired))
	}
}

func TestWithConnectTimeoutZeroUsesPerAttemptTimeout(t *testing.T) {
	ctx := WithConnectTimeout(context.Background(), 0)
	attempt, end := connectContext(ctx, 50*time.Millisecond, "connect")
	defer end()
	if remaining := time.Until(mustDeadline(t, attempt)); remaining > 50*time.Millisecond {
		t.Fatalf("attempt has %v, want at most 50ms", remaining)
	}
}

func mustDeadline(t *testing.T, ctx context.Context) time.Time {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("context has no deadline")
	}
	return deadline
}

// slowHandshakeListener delays the first read of every accepted connection,
// which delays the server side of the TLS handshake.
type slowHandshakeListener struct {
	net.Listener
	delay time.Duration
}

func (l slowHandshakeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &slowFirstReadConn{Conn: conn, delay: l.delay}, nil
}

type slowFirstReadConn struct {
	net.Conn
	delay time.Duration
	once  sync.Once
}

func (c *slowFirstReadConn) Read(p []byte) (int, error) {
	c.once.Do(func() { time.Sleep(c.delay) })
	return c.Conn.Read(p)
}

func startSlowHandshakeServer(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	server.Listener = slowHandshakeListener{Listener: server.Listener, delay: delay}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestConnectTimeoutCountsTLSHandshakeAcrossRequests(t *testing.T) {
	// Each TLS handshake takes 400ms. Two of them exceed the 600ms
	// allowance that both requests share, although each TCP dial is fast.
	first := startSlowHandshakeServer(t, 400*time.Millisecond)
	second := startSlowHandshakeServer(t, 400*time.Millisecond)
	// fetch sets the client timeout and the request allowance together.
	c := NewClient(ClientConfig{Insecure: true, ConnectTimeout: 600 * time.Millisecond})
	defer c.Close()
	ctx := WithConnectTimeout(context.Background(), 600*time.Millisecond)

	get := func(rawURL string) error {
		req, err := c.NewRequest(ctx, RequestConfig{URL: mustURL(t, rawURL)})
		if err != nil {
			return err
		}
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.Body.Close()
	}
	if err := get(first.URL); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if err := get(second.URL); err == nil {
		t.Fatal("second request succeeded, want a connect timeout for the shared allowance")
	}
}
