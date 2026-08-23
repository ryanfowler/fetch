package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/body"
	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/digest"
)

// retryableRequest executes an HTTP request with one wall-clock budget shared
// by all attempts, redirects, response reads, drains, and retry delays.
func retryableRequest(ctx context.Context, r *Request, c *client.Client, req *http.Request) (int, error) {
	if err := contextCause(ctx); err != nil {
		return 0, err
	}
	maxAttempts, err := retryAttemptCount(r.Retry)
	if err != nil {
		return 0, err
	}
	requestBudget, err := core.NewBudget(r.Timeout)
	if err != nil {
		return 0, err
	}
	connectBudget, err := core.NewBudget(r.ConnectTimeout)
	if err != nil {
		return 0, err
	}

	// Keep request-construction context values, such as the response encoding
	// policy and body source, while attaching one absolute request deadline.
	parent, stopParent := combineContexts(ctx, req.Context())
	defer stopParent()
	requestCtx, cancelBudget := requestBudget.WithContext(parent, "")
	defer cancelBudget()
	if connectBudget.Limited() {
		requestCtx = client.WithConnectBudget(requestCtx, connectBudget)
	}

	// A retry or Digest challenge needs an independent body stream. Reject a
	// one-shot source before the first network operation instead of buffering it
	// implicitly.
	var replayer *replayableBody
	if (maxAttempts > 1 && retryMethodAllowed(req.Method, r.RetryUnsafe)) || r.Digest != nil {
		replayer, err = newReplayableBody(req.WithContext(requestCtx))
		if err != nil {
			return 0, err
		}
		if replayer != nil {
			defer replayer.close()
			req.GetBody = replayer.open
		}
	}

	var hadRedirects bool
	var compressedSSERetried bool
	for attempt := range maxAttempts {
		if err := contextCause(requestCtx); err != nil {
			return 0, err
		}

		if replayer != nil {
			requestBody, err := replayer.reset()
			if err != nil {
				return 0, err
			}
			req.Body = requestBody
		}

		// A per-attempt cancel is used only to stop a completed attempt. It does
		// not create a second timeout or reset the shared request deadline.
		attemptCtx, cancelAttempt := context.WithCancel(requestCtx)
		attemptReq := req.WithContext(attemptCtx)

		var metrics *connectionMetrics
		if r.Verbosity >= core.VDebug || r.Timing || r.harRecorder != nil {
			var p *core.Printer
			if r.Verbosity >= core.VDebug {
				p = r.PrinterHandle.Stderr()
			}
			var trace *httptrace.ClientTrace
			trace, metrics = newDebugTrace(p)
			traceCtx := httptrace.WithClientTrace(attemptReq.Context(), trace)
			attemptReq = attemptReq.WithContext(client.WithDialTimingSelector(traceCtx, metrics))
		}

		if r.Verbosity >= core.VVerbose {
			attemptReq = attemptReq.WithContext(client.WithRedirectCallback(attemptReq.Context(), func(hop client.RedirectHop) {
				hadRedirects = true
				printRedirectHop(r.PrinterHandle.Stderr(), r.Verbosity, hop, r.HTTP)
			}))
		}

		if err := signAWSRequest(r, attemptReq); err != nil {
			cancelAttempt()
			return 0, err
		}

		// Redirects are created inside net/http. Re-sign each same-origin
		// redirected request after its method, URL, body, and Host are final.
		var observerErr error
		if r.AWSSigv4 != nil {
			attemptOrigin := attemptReq.URL
			attemptReq = attemptReq.WithContext(client.WithRequestObserver(attemptReq.Context(), func(next *http.Request) {
				if client.RedirectCrossedOrigin(next) || !client.SameOrigin(attemptOrigin, next.URL) {
					clearAWSHeaders(next)
					return
				}
				if next.Response != nil {
					clearAWSGeneratedHeaders(next)
				}
				if observerErr == nil {
					observerErr = signAWSRequest(r, next)
				}
			}))
		}

		resp, doErr := doOnce(r, c, attemptReq, replayer)
		if doErr == nil && observerErr != nil {
			doErr = observerErr
		}

		// Retry one safe GET/HEAD compressed SSE response without generated
		// encoding. The retry uses this attempt's context and therefore the same
		// request budget.
		if !compressedSSERetried && isCompressedSSEResponse(resp) {
			compressedSSERetried = true
			if isSafeStreamingMethod(attemptReq.Method) {
				if retryReq, ok := client.UncompressedRequest(attemptReq); ok {
					drainCompressedSSE(resp.Body, attemptReq.Context())
					_ = resp.Body.Close()
					if err := contextCause(attemptReq.Context()); err != nil {
						cancelAttempt()
						return 0, err
					}
					if err := signAWSRequest(r, retryReq); err != nil {
						cancelAttempt()
						return 0, err
					}
					resp, doErr = doOnce(r, c, retryReq, replayer)
				}
			} else if client.AutomaticCompressionEnabled(attemptReq) {
				warnCompressedSSE(r)
			}
		}

		retryable, retryAfter := shouldRetry(attemptReq.Method, r.RetryUnsafe, resp, doErr)
		isLastAttempt := attempt == maxAttempts-1
		if !retryable || isLastAttempt {
			defer cancelAttempt()
			if doErr != nil {
				return 0, doErr
			}
			if resp == nil {
				return 0, errors.New("request completed without a response")
			}
			defer func() { _ = resp.Body.Close() }()
			return processResponse(requestCtx, r, resp, hadRedirects, attempt > 0, metrics)
		}

		if resp != nil {
			if err := drainResponseBody(requestCtx, resp.Body); err != nil && contextCause(requestCtx) != nil {
				_ = resp.Body.Close()
				cancelAttempt()
				return 0, contextCause(requestCtx)
			}
			_ = resp.Body.Close()
		}
		cancelAttempt()

		delay := computeDelay(r.RetryDelay, attempt, retryAfter)
		if retryAfterWasClamped(resp) {
			warnRetryAfterClamped(r)
		}
		reason := retryReason(resp, doErr)
		printRetryMsg(r, attempt+2, maxAttempts, delay, reason)

		if err := delayFits(requestCtx, requestBudget, delay); err != nil {
			return 0, errors.Join(err, retryCause(resp, doErr))
		}
		if err := sleepWithContext(requestCtx, delay); err != nil {
			return 0, contextCauseOr(err, requestCtx)
		}
		hadRedirects = false
	}

	return 0, nil
}

const (
	maxRetryDrainBytes = 2 << 10
	maxRetryDrainTime  = 100 * time.Millisecond
)

// drainResponseBody reads only a bounded prefix and has a child deadline. A
// live or malicious response cannot hold a retry indefinitely.
func drainResponseBody(parent context.Context, source io.Reader) error {
	if source == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, maxRetryDrainTime)
	defer cancel()
	stop := closeReaderOnContext(ctx, source)
	defer stop()
	_, _ = io.CopyN(io.Discard, source, maxRetryDrainBytes)
	if parent.Err() != nil {
		return contextCause(parent)
	}
	// Draining is a best-effort connection-reuse optimization. A response
	// that closes or fails while being drained must not hide the retry cause.
	return nil
}

func retryAttemptCount(retries int) (int, error) {
	if retries < 0 {
		return 0, errors.New("retry count must be non-negative")
	}
	if retries == int(^uint(0)>>1) {
		return 0, errors.New("retry count is too large")
	}
	return retries + 1, nil
}

func combineContexts(cancellation, values context.Context) (context.Context, func()) {
	if cancellation == nil {
		cancellation = context.Background()
	}
	if values == nil {
		values = context.Background()
	}
	merged, cancel := context.WithCancelCause(values)
	stop := context.AfterFunc(cancellation, func() {
		cause := context.Cause(cancellation)
		if cause == nil {
			cause = cancellation.Err()
		}
		cancel(cause)
	})
	return merged, func() {
		stop()
		cancel(nil)
	}
}

func contextCause(ctx context.Context) error {
	if ctx == nil || ctx.Err() == nil {
		return nil
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return ctx.Err()
}

func retryCause(resp *http.Response, err error) error {
	if err != nil {
		return err
	}
	if resp != nil {
		return fmt.Errorf("last response: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return errors.New("last attempt failed without a response")
}

func contextCauseOr(err error, ctx context.Context) error {
	if cause := contextCause(ctx); cause != nil {
		return cause
	}
	return err
}

func delayFits(ctx context.Context, budget core.Budget, delay time.Duration) error {
	if err := contextCause(ctx); err != nil {
		return err
	}
	if delay <= 0 {
		return nil
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= delay {
		if budgetDeadline, limited := budget.Deadline(); limited && !deadline.Before(budgetDeadline) {
			return budget.TimeoutError("retry delay")
		}
		return context.DeadlineExceeded
	}
	return nil
}

func clearAWSGeneratedHeaders(req *http.Request) {
	if req == nil {
		return
	}
	for _, name := range []string{"Authorization", "X-Amz-Date", "X-Amz-Content-Sha256"} {
		for key := range req.Header {
			if strings.EqualFold(key, name) {
				delete(req.Header, key)
			}
		}
	}
}

func clearAWSHeaders(req *http.Request) {
	if req == nil {
		return
	}
	for _, name := range []string{"Authorization", "X-Amz-Date", "X-Amz-Content-Sha256", "X-Amz-Security-Token", "X-Amz-Session-Token"} {
		for key := range req.Header {
			if strings.EqualFold(key, name) {
				delete(req.Header, key)
			}
		}
	}
}

const maxDigestStaleRetries = 1

// doOnce performs a request and the bounded Digest challenge-response
// lifecycle. The client is deliberately supplied by the caller and remains
// alive while the authenticated response body is consumed. This matters for
// transports whose response stream is owned by a connection pool.
func doOnce(r *Request, c *client.Client, req *http.Request, replayer *replayableBody) (*http.Response, error) {
	resp, err := c.Do(req)
	if err != nil || resp == nil || r.Digest == nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}

	staleRetries := 0
	authenticatedRetry := false
	currentReq := req
	for {
		wwwAuth := findDigestChallenge(resp.Header)
		if wwwAuth == "" {
			return resp, nil
		}

		chal, err := digest.ParseChallenge(wwwAuth)
		if err != nil {
			return rejectDigestResponse(resp, fmt.Errorf("invalid digest authentication challenge: %w", err))
		}

		challengedReq := resp.Request
		if challengedReq == nil {
			challengedReq = currentReq
		}
		// Digest credentials are scoped to the request origin. A challenge after
		// a cross-origin redirect must not cause credentials for the original
		// origin to be sent to the redirected host.
		if client.RedirectCrossedOrigin(challengedReq) || !client.SameOrigin(req.URL, challengedReq.URL) {
			return resp, nil
		}

		// A second challenge is useful only when the server explicitly marks its
		// nonce stale. Limit this path so a hostile server cannot create an
		// authentication retry loop.
		if authenticatedRetry {
			if !strings.EqualFold(strings.TrimSpace(chal.Stale), "true") || staleRetries >= maxDigestStaleRetries {
				return resp, nil
			}
			staleRetries++
		}

		auth, err := digest.Response(challengedReq, chal, r.Digest.Key, r.Digest.Val)
		if err != nil {
			return rejectDigestResponse(resp, fmt.Errorf("unsupported digest authentication challenge: %w", err))
		}

		// Replay the request body only if the challenged request still has one.
		var requestBody io.ReadCloser
		if challengedReq.Body != nil && challengedReq.Body != http.NoBody {
			if replayer != nil {
				requestBody, err = replayer.reset()
			} else if challengedReq.GetBody != nil {
				requestBody, err = challengedReq.GetBody()
			} else {
				err = body.ErrNotReplayable
			}
			if err != nil {
				return rejectDigestResponse(resp, fmt.Errorf("digest authentication requires a replayable request body: %w", err))
			}
		}

		// Drain only a bounded prefix. Closing the challenge response before the
		// authenticated response is returned also prevents an unread challenge
		// body from leaking a transport resource.
		if err := drainResponseBody(challengedReq.Context(), resp.Body); err != nil {
			if cause := contextCause(challengedReq.Context()); cause != nil {
				_ = resp.Body.Close()
				if requestBody != nil {
					_ = requestBody.Close()
				}
				return nil, cause
			}
		}
		_ = resp.Body.Close()

		req2 := challengedReq.Clone(challengedReq.Context())
		req2.Body = requestBody
		if replayer != nil {
			req2.GetBody = replayer.open
		}
		req2.Header.Set("Authorization", auth)

		// Keep c alive: callers consume the returned body before their normal
		// client cleanup runs. Do not create a short-lived client for this retry.
		resp, err = c.Do(req2)
		if err != nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
			return resp, err
		}
		currentReq = req2
		authenticatedRetry = true
	}
}

func rejectDigestResponse(resp *http.Response, err error) (*http.Response, error) {
	if resp != nil {
		ctx := context.Background()
		if resp.Request != nil && resp.Request.Context() != nil {
			ctx = resp.Request.Context()
		}
		_ = drainResponseBody(ctx, resp.Body)
		_ = resp.Body.Close()
	}
	return nil, err
}

// findDigestChallenge searches the WWW-Authenticate headers for a Digest
// challenge and returns it if found.
func findDigestChallenge(h http.Header) string {
	for _, v := range h.Values("WWW-Authenticate") {
		if chal := extractDigestChallenge(v); chal != "" {
			return chal
		}
	}
	return ""
}

// extractDigestChallenge searches a single WWW-Authenticate header value for a
// Digest challenge and returns just that challenge if found.
func extractDigestChallenge(v string) string {
	upper := strings.ToUpper(v)
	if strings.HasPrefix(upper, "DIGEST ") {
		return extractDigestFrom(v, 0)
	}

	inQuotes := false
	escaped := false
	for i := 0; i < len(upper); i++ {
		c := v[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			inQuotes = !inQuotes
			continue
		}
		if inQuotes {
			continue
		}
		if strings.HasPrefix(upper[i:], "DIGEST ") {
			if i > 0 {
				prev := v[i-1]
				if prev != ' ' && prev != ',' {
					continue
				}
			}
			return extractDigestFrom(v, i)
		}
	}
	return ""
}

func extractDigestFrom(v string, start int) string {
	end := len(v)
	inQuotes := false
	escaped := false
	for j := start + 6; j < len(v); j++ {
		c := v[j]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes && (c == ',' || c == ' ') {
			rest := strings.TrimSpace(v[j+1:])
			if isKnownScheme(rest) {
				end = j
				break
			}
		}
	}
	return strings.TrimSpace(v[start:end])
}

// isKnownScheme reports whether s starts with a known HTTP authentication
// scheme name followed by a space.
func isKnownScheme(s string) bool {
	upper := strings.ToUpper(s)
	for _, scheme := range []string{
		"BASIC ", "BEARER ", "DIGEST ", "NEGOTIATE ", "NTLM ", "HOBA ",
		"MUTUAL ", "SCRAM-SHA-1 ", "SCRAM-SHA-256 ", "AWS4-HMAC-SHA256 ",
	} {
		if strings.HasPrefix(upper, scheme) {
			return true
		}
	}
	return false
}

const (
	maxCompressedSSEDrainBytes = 64 << 10
	compressedSSEDrainTimeout  = 100 * time.Millisecond
)

func isSafeStreamingMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func isCompressedSSEResponse(resp *http.Response) bool {
	if resp == nil || resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "text/event-stream") {
		return false
	}
	for _, value := range resp.Header.Values("Content-Encoding") {
		for encoding := range strings.SplitSeq(value, ",") {
			switch strings.ToLower(strings.TrimSpace(encoding)) {
			case "gzip", "br", "zstd":
				return true
			}
		}
	}
	return false
}

// drainCompressedSSE reads only a small prefix before closing the first
// response. The short child deadline is important for a live stream: waiting
// for EOF would defeat the retry and could leave a request goroutine blocked.
func drainCompressedSSE(body io.Reader, parent context.Context) {
	closer, ok := body.(io.Closer)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(parent, compressedSSEDrainTimeout)
	defer cancel()
	stop := closeReaderOnContext(ctx, body)
	defer stop()

	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxCompressedSSEDrainBytes))
	_ = closer.Close()
}

func warnCompressedSSE(r *Request) {
	if r == nil || r.Verbosity == core.VSilent {
		return
	}
	core.WriteWarningMsg(r.PrinterHandle.Stderr(), "compressed SSE was not retried without Accept-Encoding because the request method is not safe")
}

// shouldRetry determines if a request should be retried based on its method,
// response, or error. Automatic retries are limited to methods whose standard
// semantics are safe to repeat unless the caller explicitly opts into
// retrying unsafe methods. Digest challenge replays are handled separately by
// doOnce and do not use this policy.
func shouldRetry(method string, retryUnsafe bool, resp *http.Response, err error) (retryable bool, retryAfter time.Duration) {
	if !retryMethodAllowed(method, retryUnsafe) {
		return false, 0
	}
	if err != nil {
		return isRetryableError(err), 0
	}
	if resp == nil {
		return false, 0
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, // 429
		http.StatusBadGateway,         // 502
		http.StatusServiceUnavailable, // 503
		http.StatusGatewayTimeout:     // 504
		return true, parseRetryAfter(resp.Header)
	default:
		return false, 0
	}
}

func retryMethodAllowed(method string, retryUnsafe bool) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		// PUT and DELETE are idempotent in the HTTP specification, but an
		// application may still implement them with side effects that are not
		// safe to replay. Treat them like POST, PATCH, and custom methods and
		// require the same explicit opt-in.
		return retryUnsafe
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
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		return isRetryableError(urlErr.Err)
	}

	// Retry on per-attempt timeout (ErrRequestTimedOut is the custom
	// cause set via context.WithTimeoutCause for --timeout).
	if _, ok := errors.AsType[core.ErrRequestTimedOut](err); ok {
		return true
	}

	// Retry on net.Error (includes timeouts, DNS errors, and connection errors).
	_, ok := errors.AsType[net.Error](err)
	return ok
}

// parseRetryAfter parses the Retry-After header value. It supports both
// integer seconds and HTTP-date formats.
func parseRetryAfter(h http.Header) time.Duration {
	delay, _ := parseRetryAfterAt(h, time.Now())
	return delay
}

func parseRetryAfterAt(h http.Header, now time.Time) (time.Duration, bool) {
	val := strings.TrimSpace(h.Get("Retry-After"))
	if val == "" {
		return 0, false
	}

	// Delta-seconds is an unsigned decimal value. Values that do not fit in a
	// duration are valid server delays for our purposes, so clamp them rather
	// than overflowing or silently treating them as zero.
	if isDecimalValue(val) {
		secs, err := strconv.ParseUint(val, 10, 64)
		if err != nil || secs > uint64(core.MaxRetryAfter/time.Second) {
			return core.MaxRetryAfter, true
		}
		return time.Duration(secs) * time.Second, false
	}

	if t, err := http.ParseTime(val); err == nil {
		delay := t.Sub(now)
		if delay <= 0 {
			return 0, false
		}
		if delay > core.MaxRetryAfter {
			return core.MaxRetryAfter, true
		}
		return delay, false
	}

	return 0, false
}

func isDecimalValue(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func retryAfterWasClamped(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	_, clamped := parseRetryAfterAt(resp.Header, time.Now())
	return clamped
}

func warnRetryAfterClamped(r *Request) {
	if r == nil || r.Verbosity == core.VSilent {
		return
	}
	core.WriteWarningMsgIf(r.PrinterHandle.Stderr(), "server Retry-After was clamped to 30s", false)
}

// computeDelay calculates the delay before the next retry using exponential
// backoff with jitter. The formula is: min(initialDelay * 2^attempt, 30s) ± 25% jitter.
// If retryAfter exceeds the computed delay, retryAfter is used instead.
func computeDelay(initialDelay time.Duration, attempt int, retryAfter time.Duration) time.Duration {
	if initialDelay <= 0 {
		initialDelay = time.Second
	}
	if initialDelay > core.MaxRetryAfter {
		initialDelay = core.MaxRetryAfter
	}
	if attempt < 0 {
		attempt = 0
	}

	// Exponential backoff with checked/saturating arithmetic.
	delay := initialDelay
	for range attempt {
		if delay >= core.MaxRetryAfter || delay > time.Duration(math.MaxInt64/2) {
			delay = core.MaxRetryAfter
			break
		}
		delay *= 2
		if delay > core.MaxRetryAfter {
			delay = core.MaxRetryAfter
			break
		}
	}

	// Apply the existing ±25% jitter to the product backoff. Retry-After is
	// never jittered and is capped independently below.
	jitter := float64(delay) * 0.25
	delay = time.Duration(float64(delay) + (rand.Float64()*2-1)*jitter)
	if delay > core.MaxRetryAfter {
		delay = core.MaxRetryAfter
	}
	if retryAfter < 0 {
		retryAfter = 0
	}
	if retryAfter > core.MaxRetryAfter {
		retryAfter = core.MaxRetryAfter
	}
	return max(delay, retryAfter)
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

// replayableBody reopens a request body for each retry attempt.
type replayableBody struct {
	open    func() (io.ReadCloser, error)
	cleanup func() error
}

// newReplayableBody creates a replayableBody from the request's current body.
// If the body is nil or NoBody, it returns nil.
func newReplayableBody(req *http.Request) (*replayableBody, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}

	// Request construction attaches the source so retry/authentication can
	// reject one-shot input before a network operation begins. This avoids
	// silently buffering stdin or a large generated stream just because a
	// later operation might need a replay.
	if source, ok := body.SourceFromContext(req.Context()); ok {
		if !source.Replayable() {
			return nil, body.ErrNotReplayable
		}
		// The request body may be replaced with one of these replay streams
		// during a retry or Digest challenge. Keep the source lifecycle on the
		// replayer so cleanup still runs when that replacement hides the
		// original body from the caller's deferred Close.
		return &replayableBody{open: source.Replay, cleanup: source.Close}, nil
	}

	if req.GetBody != nil {
		if err := req.Body.Close(); err != nil {
			return nil, err
		}
		return &replayableBody{open: req.GetBody}, nil
	}

	if f, ok := req.Body.(*os.File); ok && f != os.Stdin {
		offset, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, err
		}
		path := f.Name()
		if err := f.Close(); err != nil {
			return nil, err
		}
		return &replayableBody{
			open: func() (io.ReadCloser, error) {
				reopened, err := os.Open(path)
				if err != nil {
					return nil, err
				}
				if offset != 0 {
					if _, err := reopened.Seek(offset, io.SeekStart); err != nil {
						reopened.Close()
						return nil, err
					}
				}
				return reopened, nil
			},
		}, nil
	}

	return nil, body.ErrNotReplayable
}

// reset returns a fresh io.ReadCloser for the next attempt.
func (rb *replayableBody) reset() (io.ReadCloser, error) {
	if rb == nil {
		return nil, nil
	}
	return rb.open()
}

func (rb *replayableBody) close() error {
	if rb == nil || rb.cleanup == nil {
		return nil
	}
	err := rb.cleanup()
	rb.cleanup = nil
	return err
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
	p.WriteString(core.TerminalSafeText(reason))
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
