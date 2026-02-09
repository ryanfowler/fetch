package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"time"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
)

// retryableRequest executes an HTTP request with optional retry logic and
// per-attempt timeout.
func retryableRequest(ctx context.Context, r *Request, c *client.Client, req *http.Request) (int, error) {
	maxAttempts := max(r.Retry+1, 1)

	// Buffer the request body so it can be replayed on retries.
	var replayer *replayableBody
	if maxAttempts > 1 {
		var err error
		replayer, err = newReplayableBody(req)
		if err != nil {
			return 0, err
		}
	}

	var hadRedirects bool
	for attempt := range maxAttempts {
		// Check for cancellation before each attempt.
		if err := ctx.Err(); err != nil {
			return 0, context.Cause(ctx)
		}

		// Reset request body for this attempt.
		if replayer != nil {
			body, err := replayer.reset()
			if err != nil {
				return 0, err
			}
			req.Body = body
		}

		// Apply per-attempt timeout. Derive from req.Context() (not ctx)
		// to preserve context values set during request construction
		// (e.g. the encoding-requested flag used for decompression).
		reqCtx := req.Context()
		var attemptCtx context.Context
		var cancelAttempt context.CancelFunc
		if r.Timeout > 0 {
			cause := core.ErrRequestTimedOut{Timeout: r.Timeout}
			attemptCtx, cancelAttempt = context.WithTimeoutCause(reqCtx, r.Timeout, cause)
		} else {
			attemptCtx, cancelAttempt = context.WithCancel(reqCtx)
		}

		attemptReq := req.WithContext(attemptCtx)

		// Set up debug trace for this attempt if -vvv or --timing.
		var metrics *connectionMetrics
		if r.Verbosity >= core.VDebug || r.Timing {
			var p *core.Printer
			if r.Verbosity >= core.VDebug {
				p = r.PrinterHandle.Stderr()
			}
			var trace *httptrace.ClientTrace
			trace, metrics = newDebugTrace(p)
			attemptReq = attemptReq.WithContext(httptrace.WithClientTrace(attemptReq.Context(), trace))
		}

		// Set up redirect callback context for this attempt.
		if r.Verbosity >= core.VVerbose {
			attemptReq = attemptReq.WithContext(client.WithRedirectCallback(attemptReq.Context(), func(hop client.RedirectHop) {
				hadRedirects = true
				printRedirectHop(r.PrinterHandle.Stderr(), r.Verbosity, hop, r.HTTP)
			}))
		}

		resp, doErr := c.Do(attemptReq)

		retryable, retryAfter := shouldRetry(resp, doErr)
		isLastAttempt := attempt == maxAttempts-1

		if !retryable || isLastAttempt {
			defer cancelAttempt()
			if doErr != nil {
				return 0, doErr
			}
			defer resp.Body.Close()
			return processResponse(ctx, r, resp, hadRedirects, attempt > 0, metrics)
		}

		// Drain and close the response body before retrying.
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		cancelAttempt()

		// Compute delay and sleep.
		delay := computeDelay(r.RetryDelay, attempt, retryAfter)
		reason := retryReason(resp, doErr)
		printRetryMsg(r, attempt+2, maxAttempts, delay, reason)

		if err := sleepWithContext(ctx, delay); err != nil {
			return 0, context.Cause(ctx)
		}

		// Reset redirect tracking for next attempt.
		hadRedirects = false
	}

	// Unreachable, but the compiler needs it.
	return 0, nil
}

// shouldRetry determines if a request should be retried based on the response
// or error. It returns whether the request is retryable and any Retry-After
// duration from the response headers.
func shouldRetry(resp *http.Response, err error) (retryable bool, retryAfter time.Duration) {
	if err != nil {
		return isRetryableError(err), 0
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests: // 429
		return true, parseRetryAfter(resp.Header)
	case http.StatusBadGateway, // 502
		http.StatusServiceUnavailable, // 503
		http.StatusGatewayTimeout:     // 504
		return true, 0
	default:
		return false, 0
	}
}

// isRetryableError returns true if the error is a transient network error
// that warrants a retry.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Don't retry on context cancellation (user pressed Ctrl+C).
	if errors.Is(err, context.Canceled) {
		return false
	}

	// Don't retry on TLS certificate errors.
	if isCertificateErr(err) {
		return false
	}

	// Unwrap URL errors first — *url.Error implements net.Error, so it
	// must be checked before the net.Error catch-all to avoid treating
	// every *url.Error (e.g. "exceeded maximum number of redirects") as
	// retryable. Instead, evaluate the inner error on its own merits.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return isRetryableError(urlErr.Err)
	}

	// Retry on per-attempt timeout (ErrRequestTimedOut is the custom
	// cause set via context.WithTimeoutCause for --timeout).
	var timedOut core.ErrRequestTimedOut
	if errors.As(err, &timedOut) {
		return true
	}

	// Retry on net.Error (includes timeouts, DNS errors, and connection errors).
	var netErr net.Error
	return errors.As(err, &netErr)
}

// parseRetryAfter parses the Retry-After header value. It supports both
// integer seconds and HTTP-date formats.
func parseRetryAfter(h http.Header) time.Duration {
	val := h.Get("Retry-After")
	if val == "" {
		return 0
	}

	// Try integer seconds first.
	if secs, err := strconv.Atoi(val); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}

	// Try HTTP-date format.
	if t, err := http.ParseTime(val); err == nil {
		d := time.Until(t)
		if d < 0 {
			return 0
		}
		return d
	}

	return 0
}

// computeDelay calculates the delay before the next retry using exponential
// backoff with jitter. The formula is: min(initialDelay * 2^attempt, 30s) ± 25% jitter.
// If retryAfter exceeds the computed delay, retryAfter is used instead.
func computeDelay(initialDelay time.Duration, attempt int, retryAfter time.Duration) time.Duration {
	if initialDelay <= 0 {
		initialDelay = time.Second
	}

	// Exponential backoff: initialDelay * 2^attempt.
	delay := initialDelay
	for range attempt {
		delay *= 2
		if delay > 30*time.Second {
			delay = 30 * time.Second
			break
		}
	}

	// Apply jitter: ±25%.
	jitter := float64(delay) * 0.25
	delay = time.Duration(float64(delay) + (rand.Float64()*2-1)*jitter)

	// Respect Retry-After if it's larger.
	delay = max(delay, retryAfter)

	return delay
}

// sleepWithContext sleeps for the given duration, returning early if the
// context is cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// replayableBody allows a request body to be replayed across retry attempts.
type replayableBody struct {
	seeker io.ReadSeeker
	data   []byte
}

// newReplayableBody creates a replayableBody from the request's current body.
// If the body is nil or NoBody, it returns nil.
func newReplayableBody(req *http.Request) (*replayableBody, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}

	// If the body supports seeking, use it directly.
	if rs, ok := req.Body.(io.ReadSeeker); ok {
		return &replayableBody{seeker: rs}, nil
	}

	// Otherwise, read the entire body into memory.
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body.Close()
	return &replayableBody{data: data}, nil
}

// reset returns a fresh io.ReadCloser for the next attempt.
func (rb *replayableBody) reset() (io.ReadCloser, error) {
	if rb.seeker != nil {
		if _, err := rb.seeker.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return io.NopCloser(rb.seeker), nil
	}
	return io.NopCloser(bytes.NewReader(rb.data)), nil
}

// retryReason returns a human-readable reason for the retry.
func retryReason(resp *http.Response, err error) string {
	if err != nil {
		return err.Error()
	}
	if resp != nil {
		return fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return "unknown"
}

// printRetryMsg prints a compact retry notification to stderr.
func printRetryMsg(r *Request, nextAttempt, total int, delay time.Duration, reason string) {
	if r.Verbosity == core.VSilent {
		return
	}

	p := r.PrinterHandle.Stderr()
	if r.Verbosity >= core.VExtraVerbose {
		p.WriteInfoPrefix()
	}
	p.Set(core.Bold)
	p.Set(core.Yellow)
	p.WriteString("retry")
	p.Reset()
	p.WriteString(": ")

	fmt.Fprintf(p, "attempt %d/%d in %s", nextAttempt, total, formatDelay(delay))

	p.WriteString(" ")
	p.Set(core.Dim)
	p.WriteString("(")
	p.WriteString(reason)
	p.WriteString(")")
	p.Reset()
	p.WriteString("\n")
	p.Flush()
}

// formatDelay formats a duration for display in retry messages.
func formatDelay(d time.Duration) string {
	if d < time.Millisecond {
		return "0s"
	}
	if d < time.Second {
		ms := float64(d) / float64(time.Millisecond)
		return fmt.Sprintf("%.0fms", ms)
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
