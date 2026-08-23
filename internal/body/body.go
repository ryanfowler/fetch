// Package body contains the request-body and response-stream primitives used
// by the fetch request pipeline.
package body

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/ryanfowler/fetch/internal/core"
)

var (
	// ErrNotReplayable is returned when an operation needs a second request
	// stream but the original source can only be consumed once.
	ErrNotReplayable = errors.New("request body is not replayable")
	// ErrBodyAlreadyOpen is returned when a one-shot body has already been
	// handed to a caller and another independent stream is requested.
	ErrBodyAlreadyOpen = errors.New("request body has already been opened")
)

// Preview is a bounded, non-destructive view of a body. Data may contain at
// most Limit bytes. Truncated is true when at least one further byte exists.
type Preview struct {
	Data      []byte
	Truncated bool
}

// Body describes one request-body source. A Body is lazy: constructing it
// does not read stdin, open a file stream, or consume a generated body. The
// first Read opens the source, while Replay opens a fresh stream when the
// source is replayable.
type Body struct {
	mu          sync.Mutex
	lifecycle   sync.Mutex
	open        func() (io.ReadCloser, error)
	contentType string
	length      int64
	replayable  bool

	started bool
	active  io.ReadCloser
	pending *pending

	cleanup     func() error
	cleanupOnce sync.Once
	cleanupErr  error
}

type pending struct {
	prefix []byte
	rest   io.ReadCloser
	done   bool
}

// NewFactory creates a body from a stream factory. length must be -1 when
// unknown. A replayable factory must return an independent stream each time.
func NewFactory(open func() (io.ReadCloser, error), length int64, contentType string, replayable bool) *Body {
	if open == nil {
		panic("body: nil stream factory")
	}
	if length < -1 {
		length = -1
	}
	return &Body{open: open, contentType: contentType, length: length, replayable: replayable}
}

// NewBytes creates a replayable in-memory body.
func NewBytes(data []byte, contentType string) *Body {
	copyData := bytes.Clone(data)
	return NewFactory(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(copyData)), nil
	}, int64(len(copyData)), contentType, true)
}

// NewReader creates a one-shot body from r.
func NewReader(r io.Reader, length int64, contentType string) *Body {
	if r == nil {
		panic("body: nil reader")
	}
	var once sync.Once
	return NewFactory(func() (io.ReadCloser, error) {
		var opened bool
		once.Do(func() {
			opened = true
		})
		if !opened {
			return nil, ErrNotReplayable
		}
		if rc, ok := r.(io.ReadCloser); ok {
			return rc, nil
		}
		return io.NopCloser(r), nil
	}, length, contentType, false)
}

// NewSeekable creates a one-shot body over a seekable reader. A general
// ReadSeeker shares one mutable cursor, so it cannot safely provide concurrent
// independent replay streams.
func NewSeekable(r io.ReadSeeker, offset, length int64, contentType string) *Body {
	if r == nil {
		panic("body: nil seekable reader")
	}
	var once sync.Once
	return NewFactory(func() (io.ReadCloser, error) {
		var first bool
		once.Do(func() { first = true })
		if !first {
			return nil, ErrNotReplayable
		}
		if _, err := r.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
		return &readSeekCloser{ReadSeeker: r}, nil
	}, length, contentType, false)
}

// NewReaderAt creates independent replay streams over a random-access source.
func NewReaderAt(r io.ReaderAt, offset, length int64, contentType string) *Body {
	if r == nil {
		panic("body: nil reader-at")
	}
	return NewFactory(func() (io.ReadCloser, error) {
		return io.NopCloser(io.NewSectionReader(r, offset, length)), nil
	}, length, contentType, true)
}

// NewFile creates a replayable, exact-length body for a regular file. Each
// open verifies that the path still names the same regular file and has not
// changed size since argument parsing.
func NewFile(path, contentType string) (*Body, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("request body is not a regular file: %s", path)
	}
	return newFile(path, info, contentType), nil
}

// NewFileFromOpenFile converts an already-open regular file into a replayable
// source and closes the caller's descriptor. It is useful at the boundary
// where CLI parsing has already opened a file to inspect its content type.
func NewFileFromOpenFile(f *os.File, contentType string) (*Body, error) {
	if f == nil {
		return nil, errors.New("request body file is nil")
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("request body is not a regular file: %s", f.Name())
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		return nil, err
	}
	return newFile(path, info, contentType), nil
}

func newFile(path string, info os.FileInfo, contentType string) *Body {
	return NewFactory(func() (io.ReadCloser, error) {
		current, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !current.Mode().IsRegular() || !os.SameFile(info, current) {
			return nil, fmt.Errorf("request body file changed: %s", path)
		}
		if current.Size() != info.Size() {
			return nil, fmt.Errorf("request body file size changed: %s", path)
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		opened, err := f.Stat()
		if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
			f.Close()
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("request body file changed: %s", path)
		}
		return &exactFileReader{file: f, remaining: info.Size(), expected: info.Size(), identity: info, path: path}, nil
	}, info.Size(), contentType, true)
}

// ContentType reports the source's declared content type, if any.
func (b *Body) ContentType() string { return b.contentType }

// ContentLength reports the known body length, or -1 when unknown.
func (b *Body) ContentLength() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.length
}

// Replayable reports whether independent streams can be opened.
func (b *Body) Replayable() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.replayable
}

// Replay opens an independent stream. It never consumes the body's first
// stream and is intended for http.Request.GetBody and retry/authentication.
func (b *Body) Replay() (io.ReadCloser, error) {
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	b.mu.Lock()
	if !b.replayable {
		b.mu.Unlock()
		return nil, ErrNotReplayable
	}
	open := b.open
	b.mu.Unlock()
	return open()
}

// SetCleanup registers a callback run once when the body is closed. It is
// intended for sources with resources that are not owned by an individual
// stream, such as a temporary spool file.
func (b *Body) SetCleanup(cleanup func() error) {
	if cleanup == nil {
		return
	}
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	b.mu.Lock()
	b.cleanup = cleanup
	b.mu.Unlock()
}

// Preview reads at most max+1 bytes without consuming the stream that Read
// will use. For one-shot sources the unopened stream is retained and later
// Read returns the complete body, including the previewed prefix.
func (b *Body) Preview(max int64) (Preview, error) {
	if max < 0 {
		return Preview{}, core.LimitError{Subsystem: "body preview", Limit: max}
	}

	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	b.mu.Lock()
	if b.started {
		replayable := b.replayable
		open := b.open
		b.mu.Unlock()
		if !replayable {
			return Preview{}, ErrBodyAlreadyOpen
		}
		rc, err := open()
		if err != nil {
			return Preview{}, err
		}
		return previewStream(rc, max)
	}
	if b.pending != nil {
		if !b.pending.done && int64(len(b.pending.prefix)) < max+1 {
			need := max + 1 - int64(len(b.pending.prefix))
			extra, err := io.ReadAll(io.LimitReader(b.pending.rest, need))
			if err != nil {
				b.mu.Unlock()
				return Preview{}, err
			}
			b.pending.prefix = append(b.pending.prefix, extra...)
			if int64(len(extra)) < need {
				b.pending.done = true
			}
		}
		full := b.pending.prefix
		viewLen := minInt64(int64(len(full)), max)
		data := bytes.Clone(full[:viewLen])
		truncated := int64(len(full)) > max || !b.pending.done
		b.mu.Unlock()
		return Preview{Data: data, Truncated: truncated}, nil
	}
	open := b.open
	b.mu.Unlock()
	rc, err := open()
	if err != nil {
		return Preview{}, err
	}
	data, readErr := readPreview(rc, max)
	if readErr != nil {
		_ = rc.Close()
		return Preview{}, readErr
	}
	b.mu.Lock()
	b.pending = &pending{prefix: data.full, rest: rc, done: data.done}
	b.mu.Unlock()
	return data.Preview, nil
}

func previewStream(rc io.ReadCloser, max int64) (Preview, error) {
	defer rc.Close()
	data, err := readPreview(rc, max)
	return data.Preview, err
}

type previewResult struct {
	Preview
	full []byte
	done bool
}

func readPreview(rc io.ReadCloser, max int64) (previewResult, error) {
	limit := max + 1
	if max == int64(^uint64(0)>>1) {
		limit = max
	}
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil {
		return previewResult{}, err
	}
	viewLen := minInt64(int64(len(data)), max)
	return previewResult{
		Preview: Preview{Data: bytes.Clone(data[:viewLen]), Truncated: int64(len(data)) > max},
		full:    data,
		done:    int64(len(data)) <= max,
	}, nil
}

// Materialize consumes the body with a hard cap and turns it into a
// replayable in-memory body. It is for protocol conversions and signing, not
// ordinary uploads.
func (b *Body) Materialize(max int64) ([]byte, error) {
	if max < 0 {
		return nil, core.LimitError{Subsystem: "request body materialization", Limit: max}
	}

	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	b.mu.Lock()
	if b.active != nil || (b.started && b.pending == nil) {
		b.mu.Unlock()
		return nil, ErrBodyAlreadyOpen
	}
	var rc io.ReadCloser
	var err error
	if b.pending != nil {
		p := b.pending
		b.pending = nil
		b.started = true
		rc = &prefixedReadCloser{Reader: io.MultiReader(bytes.NewReader(p.prefix), p.rest), rest: p.rest}
		b.active = rc
	} else {
		rc, err = b.open()
		if err == nil {
			b.started = true
			b.active = rc
		}
	}
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	data, err := core.ReadAllLimited(rc, max, "request body materialization")
	closeErr := rc.Close()
	b.mu.Lock()
	b.active = nil
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}

	b.mu.Lock()
	b.open = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
	b.length = int64(len(data))
	b.replayable = true
	b.started = false
	b.active = nil
	b.pending = nil
	b.mu.Unlock()
	return bytes.Clone(data), nil
}

// Open returns the body's first stream. Replayable sources may also be opened
// repeatedly; one-shot sources return ErrBodyAlreadyOpen after the first
// stream has been handed out.
func (b *Body) Open() (io.ReadCloser, error) {
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending != nil {
		p := b.pending
		b.pending = nil
		b.started = true
		b.active = &prefixedReadCloser{Reader: io.MultiReader(bytes.NewReader(p.prefix), p.rest), rest: p.rest}
		return b.active, nil
	}
	if b.started {
		if !b.replayable {
			return nil, ErrBodyAlreadyOpen
		}
		return b.open()
	}
	rc, err := b.open()
	if err != nil {
		return nil, err
	}
	b.started = true
	b.active = rc
	return rc, nil
}

// Read lazily opens the first stream, making Body safe to use directly as an
// http.Request.Body without eagerly consuming stdin or files.
func (b *Body) Read(p []byte) (int, error) {
	b.lifecycle.Lock()
	b.mu.Lock()
	if b.active == nil {
		if b.pending != nil {
			pnd := b.pending
			b.pending = nil
			b.active = &prefixedReadCloser{Reader: io.MultiReader(bytes.NewReader(pnd.prefix), pnd.rest), rest: pnd.rest}
		} else {
			rc, err := b.open()
			if err != nil {
				b.mu.Unlock()
				b.lifecycle.Unlock()
				return 0, err
			}
			b.active = rc
		}
		b.started = true
	}
	rc := b.active
	b.mu.Unlock()
	b.lifecycle.Unlock()
	return rc.Read(p)
}

// Close closes the active first stream. Replay streams returned by Replay or
// Open are owned by their caller and are not affected by this method.
func (b *Body) Close() error {
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	b.mu.Lock()
	rc := b.active
	p := b.pending
	cleanup := b.cleanup
	b.active = nil
	b.pending = nil
	b.mu.Unlock()
	var closeErr error
	if rc != nil {
		closeErr = rc.Close()
	}
	if p != nil {
		closeErr = errors.Join(closeErr, p.rest.Close())
	}
	if cleanup != nil {
		b.cleanupOnce.Do(func() { b.cleanupErr = cleanup() })
		closeErr = errors.Join(closeErr, b.cleanupErr)
	}
	return closeErr
}

type readSeekCloser struct{ io.ReadSeeker }

func (readSeekCloser) Close() error { return nil }

type prefixedReadCloser struct {
	io.Reader
	rest io.Closer
}

func (r *prefixedReadCloser) Close() error { return r.rest.Close() }

type exactFileReader struct {
	file      *os.File
	remaining int64
	expected  int64
	identity  os.FileInfo
	path      string
	closeOnce sync.Once
	closeErr  error
}

func (r *exactFileReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		info, err := os.Stat(r.path)
		if err != nil {
			return 0, err
		}
		if info.Size() != r.expected || !os.SameFile(r.identity, info) {
			return 0, fmt.Errorf("request body file changed while reading: %s", r.path)
		}
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.file.Read(p)
	r.remaining -= int64(n)
	if err == io.EOF && r.remaining > 0 {
		return n, fmt.Errorf("request body file ended before its expected length: %s", r.path)
	}
	return n, err
}

func (r *exactFileReader) Close() error {
	r.closeOnce.Do(func() { r.closeErr = r.file.Close() })
	return r.closeErr
}

func minInt64(a, b int64) int {
	if a < b {
		return int(a)
	}
	return int(b)
}

type sourceContextKey struct{}

// WithSource associates a request with its body source for dry-run and
// lifecycle-aware consumers.
func WithSource(ctx context.Context, b *Body) context.Context {
	return context.WithValue(ctx, sourceContextKey{}, b)
}

// SourceFromContext returns the source attached by WithSource.
func SourceFromContext(ctx context.Context) (*Body, bool) {
	b, ok := ctx.Value(sourceContextKey{}).(*Body)
	return b, ok
}

// Attach installs b as req.Body, sets known length/GetBody, and preserves the
// source in the request context.
func Attach(req *http.Request, b *Body) {
	// Attach is used both while a request is being constructed and later when
	// an editor or protocol adapter replaces its body. Preserve wire metadata
	// explicitly supplied by the caller in the latter case. In particular,
	// changing the body must not silently turn a user-selected
	// Content-Length/Transfer-Encoding into the source's inferred length.
	explicitLength := req.Header.Get("Content-Length") != ""
	explicitTransferEncoding := len(req.TransferEncoding) > 0 || req.Header.Get("Transfer-Encoding") != ""
	if !explicitLength && !explicitTransferEncoding {
		req.ContentLength = b.ContentLength()
	}
	if b.Replayable() && req.ContentLength == 0 {
		req.Body = http.NoBody
		req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	} else if b.Replayable() {
		req.Body = b
		req.GetBody = b.Replay
	} else {
		req.Body = b
		req.GetBody = nil
	}
	*req = *req.WithContext(WithSource(req.Context(), b))
}
