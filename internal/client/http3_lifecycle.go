package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// HTTP3ErrorKind identifies the stage at which an HTTP/3 exchange failed.
// The kind is deliberately small and stable so callers can present useful
// diagnostics without parsing quic-go error strings.
type HTTP3ErrorKind uint8

const (
	HTTP3HandshakeFailure HTTP3ErrorKind = iota + 1
	HTTP3SettingsFailure
	HTTP3StreamFailure
	HTTP3BodyTimeout
	HTTP3RemoteStatusFailure
)

func (kind HTTP3ErrorKind) String() string {
	switch kind {
	case HTTP3HandshakeFailure:
		return "QUIC handshake failure"
	case HTTP3SettingsFailure:
		return "HTTP/3 settings/protocol failure"
	case HTTP3StreamFailure:
		return "HTTP/3 request stream failure"
	case HTTP3BodyTimeout:
		return "HTTP/3 response body timeout"
	case HTTP3RemoteStatusFailure:
		return "remote HTTP status"
	default:
		return "HTTP/3 failure"
	}
}

// HTTP3Error preserves the underlying error while identifying the HTTP/3
// lifecycle stage. In particular, timeout errors remain discoverable through
// errors.Is/errors.As.
type HTTP3Error struct {
	Kind HTTP3ErrorKind
	Err  error
}

// HTTP3RequestBodyError marks a failure in the upload reader. It is separate
// from a transport failure because automatic HTTP/3 must not evict a healthy
// candidate when the caller's file or stream failed.
type HTTP3RequestBodyError struct {
	Err error
}

func (e *HTTP3RequestBodyError) Error() string {
	if e == nil || e.Err == nil {
		return "HTTP/3 request body failed"
	}
	return fmt.Sprintf("HTTP/3 request body: %v", e.Err)
}

func (e *HTTP3RequestBodyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *HTTP3Error) Error() string {
	if e == nil {
		return "HTTP/3 failure"
	}
	if e.Err == nil {
		return e.Kind.String()
	}
	return fmt.Sprintf("%s: %v", e.Kind, e.Err)
}

func (e *HTTP3Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func classifyHTTP3Error(err error, setup bool) error {
	if err == nil {
		return nil
	}
	var already *HTTP3Error
	if errors.As(err, &already) {
		return err
	}
	if errors.Is(err, context.Canceled) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		if setup {
			return &HTTP3Error{Kind: HTTP3HandshakeFailure, Err: err}
		}
		return err
	}

	kind := HTTP3StreamFailure
	var h3Err *http3.Error
	var streamErr *quic.StreamError
	switch {
	case errors.As(err, &h3Err):
		if isHTTP3ProtocolError(h3Err.ErrorCode) {
			kind = HTTP3SettingsFailure
		}
	case errors.As(err, &streamErr):
		kind = HTTP3StreamFailure
	case setup:
		kind = HTTP3HandshakeFailure
	default:
		var handshakeTimeout *quic.HandshakeTimeoutError
		var transportError *quic.TransportError
		var versionError *quic.VersionNegotiationError
		if errors.As(err, &handshakeTimeout) || errors.As(err, &transportError) || errors.As(err, &versionError) {
			kind = HTTP3HandshakeFailure
		}
	}
	return &HTTP3Error{Kind: kind, Err: err}
}

type h3RoundTripper interface {
	RoundTrip(*http.Request) (*http.Response, error)
}

// roundTripHTTP3 adds the lifecycle guarantees that net/http users expect to
// an HTTP/3 transport. quic-go already resets a request stream when a body
// reader fails; this wrapper also makes that error observable, cancels the
// request when the response is abandoned, and stops its watcher at EOF.
func roundTripHTTP3(rt h3RoundTripper, req *http.Request) (*http.Response, error) {
	return roundTripHTTP3WithDone(rt, req, nil)
}

func roundTripHTTP3WithDone(rt h3RoundTripper, req *http.Request, done func()) (*http.Response, error) {
	if rt == nil {
		if done != nil {
			done()
		}
		return nil, errors.New("HTTP/3 transport is nil")
	}
	if req == nil {
		if done != nil {
			done()
		}
		return nil, errors.New("HTTP/3 request is nil")
	}
	if cause := context.Cause(req.Context()); cause != nil {
		if req.Body != nil && req.Body != http.NoBody {
			go func() { _ = req.Body.Close() }()
		}
		if done != nil {
			done()
		}
		return nil, cause
	}

	ctx, cancel := context.WithCancel(req.Context())
	sent := req.Clone(ctx)
	state := &h3RequestState{bodies: make(map[*h3RequestBody]struct{}), done: make(chan struct{}), cancel: cancel}
	go state.watchContext(ctx)
	if req.Body != nil && req.Body != http.NoBody {
		body := newH3RequestBody(req.Body, state)
		sent.Body = body
		if req.GetBody != nil {
			getBody := req.GetBody
			sent.GetBody = func() (io.ReadCloser, error) {
				replay, err := getBody()
				if err != nil {
					return nil, err
				}
				return newH3RequestBody(replay, state), nil
			}
		}
	}

	resp, err := rt.RoundTrip(sent)
	if err != nil {
		state.abort()
		state.stop()
		cancel()
		if bodyErr := state.err(); bodyErr != nil {
			if done != nil {
				done()
			}
			return nil, &HTTP3RequestBodyError{Err: bodyErr}
		}
		if done != nil {
			done()
		}
		return nil, classifyHTTP3Error(err, true)
	}
	if bodyErr := state.err(); bodyErr != nil {
		if resp != nil && resp.Body != nil {
			go func() { _ = resp.Body.Close() }()
		}
		state.abort()
		state.stop()
		cancel()
		if done != nil {
			done()
		}
		return nil, &HTTP3RequestBodyError{Err: bodyErr}
	}
	if resp == nil {
		state.abort()
		state.stop()
		cancel()
		if done != nil {
			done()
		}
		return nil, errors.New("HTTP/3 transport returned a nil response")
	}
	if resp.Body == nil {
		state.abort()
		state.stop()
		cancel()
		if done != nil {
			done()
		}
		return resp, nil
	}

	resp.Request = sent
	resp.Body = newH3ResponseBody(resp.Body, ctx, cancel, state, done)
	return resp, nil
}

type h3RequestState struct {
	mu       sync.Mutex
	bodies   map[*h3RequestBody]struct{}
	bodyErr  error
	aborted  bool
	done     chan struct{}
	cancel   context.CancelFunc
	stopOnce sync.Once
}

func (s *h3RequestState) watchContext(ctx context.Context) {
	select {
	case <-ctx.Done():
		s.abort()
	case <-s.done:
	}
}

func (s *h3RequestState) stop() {
	s.stopOnce.Do(func() { close(s.done) })
}

func (s *h3RequestState) add(body *h3RequestBody) {
	s.mu.Lock()
	aborted := s.aborted
	if !aborted {
		s.bodies[body] = struct{}{}
	}
	s.mu.Unlock()
	if aborted {
		go func() { _ = body.Close() }()
	}
}

func (s *h3RequestState) remove(body *h3RequestBody) {
	s.mu.Lock()
	delete(s.bodies, body)
	s.mu.Unlock()
}

func (s *h3RequestState) fail(err error) {
	if err == nil || err == io.EOF {
		return
	}
	s.mu.Lock()
	var cancel context.CancelFunc
	if s.bodyErr == nil && !s.aborted {
		s.bodyErr = err
		cancel = s.cancel
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *h3RequestState) err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bodyErr
}

func (s *h3RequestState) abort() {
	s.mu.Lock()
	if s.aborted {
		s.mu.Unlock()
		return
	}
	s.aborted = true
	bodies := make([]*h3RequestBody, 0, len(s.bodies))
	for body := range s.bodies {
		bodies = append(bodies, body)
	}
	s.mu.Unlock()
	if len(bodies) == 0 {
		return
	}
	// QUIC cancellation is synchronous and unblocks the transport. User body
	// Close methods are expected to be prompt, but a broken source must not
	// delay the original upload or response error. Use one bounded-per-request
	// cleanup goroutine rather than one goroutine per read or stream.
	go func() {
		for _, body := range bodies {
			_ = body.Close()
		}
	}()
}

type h3RequestBody struct {
	body  io.ReadCloser
	state *h3RequestState
	once  sync.Once
}

func newH3RequestBody(body io.ReadCloser, state *h3RequestState) *h3RequestBody {
	wrapped := &h3RequestBody{body: body, state: state}
	state.add(wrapped)
	return wrapped
}

func (b *h3RequestBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if err != nil && err != io.EOF {
		b.state.fail(err)
	}
	return n, err
}

func (b *h3RequestBody) Close() error {
	var err error
	b.once.Do(func() {
		b.state.remove(b)
		err = b.body.Close()
	})
	return err
}

type h3ResponseBody struct {
	body   io.ReadCloser
	ctx    context.Context
	cancel context.CancelFunc
	state  *h3RequestState
	onDone func()

	once sync.Once
	done chan struct{}
}

func newH3ResponseBody(body io.ReadCloser, ctx context.Context, cancel context.CancelFunc, state *h3RequestState, onDone func()) *h3ResponseBody {
	wrapped := &h3ResponseBody{body: body, ctx: ctx, cancel: cancel, state: state, onDone: onDone, done: make(chan struct{})}
	go wrapped.watchContext()
	return wrapped
}

func (b *h3ResponseBody) watchContext() {
	select {
	case <-b.ctx.Done():
		b.finish()
	case <-b.done:
	}
}

func (b *h3ResponseBody) Read(p []byte) (int, error) {
	if cause := context.Cause(b.ctx); cause != nil {
		b.finish()
		return 0, classifyHTTP3BodyCause(cause)
	}
	n, err := b.body.Read(p)
	if bodyErr := b.state.err(); bodyErr != nil {
		b.finish()
		return n, &HTTP3RequestBodyError{Err: bodyErr}
	}
	if err != nil {
		if timeoutErr := classifyHTTP3BodyCause(err); timeoutErr != err {
			var bodyTimeout *HTTP3Error
			if errors.As(timeoutErr, &bodyTimeout) && bodyTimeout.Kind == HTTP3BodyTimeout {
				b.finish()
				return n, timeoutErr
			}
		}
		// Save the underlying result before finish cancels the request context.
		// A normal EOF must remain EOF, and a stream reset must not turn into
		// the unrelated context.Canceled error caused by cleanup.
		cause := context.Cause(b.ctx)
		b.finish()
		if cause != nil {
			return n, classifyHTTP3BodyCause(cause)
		}
		if err == io.EOF {
			return n, io.EOF
		}
		return n, classifyHTTP3Error(err, false)
	}
	return n, nil
}

// HTTP3StatusError classifies a final remote HTTP status without changing
// normal response handling. A status is not a transport error, so callers that
// need the response body should keep the response and use this helper only for
// diagnostics or status policy.
func HTTP3StatusError(resp *http.Response) error {
	if resp == nil || resp.StatusCode < http.StatusBadRequest {
		return nil
	}
	status := resp.Status
	if status == "" {
		status = http.StatusText(resp.StatusCode)
	}
	return &HTTP3Error{
		Kind: HTTP3RemoteStatusFailure,
		Err:  fmt.Errorf("remote HTTP status: %s", status),
	}
}

func isHTTP3ProtocolError(code http3.ErrCode) bool {
	switch code {
	case http3.ErrCodeGeneralProtocolError,
		http3.ErrCodeInternalError,
		http3.ErrCodeStreamCreationError,
		http3.ErrCodeClosedCriticalStream,
		http3.ErrCodeFrameUnexpected,
		http3.ErrCodeFrameError,
		http3.ErrCodeExcessiveLoad,
		http3.ErrCodeIDError,
		http3.ErrCodeSettingsError,
		http3.ErrCodeMissingSettings,
		http3.ErrCodeConnectError,
		http3.ErrCodeVersionFallback,
		http3.ErrCodeDatagramError,
		http3.ErrCodeQPACKDecompressionFailed,
		http3.ErrCodeMessageError:
		return true
	default:
		return false
	}
}

func classifyHTTP3BodyCause(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &HTTP3Error{Kind: HTTP3BodyTimeout, Err: err}
	}
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		return &HTTP3Error{Kind: HTTP3BodyTimeout, Err: err}
	}
	return err
}

func (b *h3ResponseBody) Close() error {
	b.finish()
	return nil
}

func (b *h3ResponseBody) finish() {
	b.once.Do(func() {
		b.cancel()
		b.state.abort()
		b.state.stop()
		_ = b.body.Close()
		if b.onDone != nil {
			b.onDone()
		}
		close(b.done)
	})
}
