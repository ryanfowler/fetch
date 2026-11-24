package client

import (
	"context"
	"sync"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

// connectAllowance limits the total time that one request spends
// establishing connections, across redirects and retries. Only time while
// at least one connection attempt is active counts. Time spent sending the
// request or waiting for a response does not use the allowance. Concurrent
// and nested attempts, such as an address race inside a proxy dial, count
// once.
type connectAllowance struct {
	limit time.Duration
	now   func() time.Time

	mu     sync.Mutex
	used   time.Duration // time counted before the current active period
	active int           // number of attempts in progress
	since  time.Time     // start of the current active period
}

// WithConnectTimeout limits the total time that requests made with ctx spend
// establishing connections (DNS, proxy, TCP, TLS, and QUIC setup). Retries
// and redirects share the limit, so a retry cannot restart it. A timeout of
// zero or less means no limit.
func WithConnectTimeout(ctx context.Context, timeout time.Duration) context.Context {
	if timeout <= 0 {
		return ctx
	}
	return context.WithValue(ctx, ctxConnectAllowanceKey, &connectAllowance{limit: timeout, now: time.Now})
}

// begin starts a connection attempt. It returns a context that ends when the
// allowance is used up, and a function that ends the attempt. The caller
// must call that function when the attempt finishes.
func (a *connectAllowance) begin(ctx context.Context, phase string) (context.Context, context.CancelFunc) {
	a.mu.Lock()
	now := a.now()
	used := a.used
	if a.active > 0 {
		used += now.Sub(a.since)
	} else {
		a.since = now
	}
	a.active++
	a.mu.Unlock()

	cause := core.TimeoutError{Duration: a.limit, Phase: phase, Connection: true}
	attemptCtx, cancel := context.WithDeadlineCause(ctx, now.Add(a.limit-used), cause)
	var once sync.Once
	return attemptCtx, func() {
		once.Do(func() {
			cancel()
			a.end()
		})
	}
}

func (a *connectAllowance) end() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active--
	if a.active == 0 {
		a.used += a.now().Sub(a.since)
	}
}
