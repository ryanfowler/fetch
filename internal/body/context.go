package body

import (
	"context"
	"io"
	"sync"
)

// ContextReader closes source on cancellation to unblock an in-progress Read,
// and reports the context's cause instead of the resulting closed-stream error.
// source must support concurrent Read and Close for cancellation to interrupt
// a blocked read. stop detaches cancellation without closing the stream; callers
// that retain ownership of source must call it when their read operation ends.
func ContextReader(ctx context.Context, source io.ReadCloser) (io.ReadCloser, func()) {
	r := &contextReadCloser{ctx: ctx, source: source}
	// The callback uses close directly so it never accesses stop before the
	// AfterFunc call has returned, even with an already-canceled context.
	r.stop = context.AfterFunc(ctx, func() { _ = r.close() })
	return r, func() { r.stop() }
}

type contextReadCloser struct {
	ctx    context.Context
	source io.ReadCloser
	stop   func() bool
	once   sync.Once
	err    error
}

func (r *contextReadCloser) Read(p []byte) (int, error) {
	if err := context.Cause(r.ctx); err != nil {
		return 0, err
	}
	n, err := r.source.Read(p)
	if cause := context.Cause(r.ctx); cause != nil {
		err = cause
	}
	return n, err
}

func (r *contextReadCloser) Close() error {
	r.stop()
	return r.close()
}

func (r *contextReadCloser) close() error {
	r.once.Do(func() { r.err = r.source.Close() })
	return r.err
}
