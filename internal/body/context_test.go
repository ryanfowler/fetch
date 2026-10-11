package body

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBodyPreparationHonorsCancellation(t *testing.T) {
	for _, operation := range []string{"materialize", "preview"} {
		t.Run(operation, func(t *testing.T) {
			input, writer := io.Pipe()
			defer input.Close()
			defer writer.Close()
			reader := &contextTestInput{ReadCloser: input, started: make(chan struct{})}
			b := NewReader(reader, -1, "")
			defer b.Close()
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			result := make(chan error, 1)
			go func() {
				var err error
				if operation == "materialize" {
					_, err = b.MaterializeWithContext(ctx, 1024)
				} else {
					_, err = b.PreviewWithContext(ctx, 1024)
				}
				result <- err
			}()
			select {
			case <-reader.started:
			case <-time.After(2 * time.Second):
				t.Fatal("body preparation did not start reading")
			}
			cause := errors.New("cancel body preparation")
			cancel(cause)
			select {
			case err := <-result:
				if !errors.Is(err, cause) {
					t.Fatalf("preparation error = %v, want cancellation cause", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("body preparation deadlocked on cancellation")
			}
			if got := reader.closes.Load(); got != 1 {
				t.Fatalf("stream closed %d times, want once", got)
			}
		})
	}
}

func TestCanceledBodyPreparationDoesNotOpenSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := NewFactory(func() (io.ReadCloser, error) {
		t.Fatal("canceled operation opened the source")
		return nil, nil
	}, -1, "", true)
	if _, err := b.MaterializeWithContext(ctx, 1024); !errors.Is(err, context.Canceled) {
		t.Fatalf("materialization error = %v, want cancellation", err)
	}
	if _, err := b.PreviewWithContext(ctx, 1024); !errors.Is(err, context.Canceled) {
		t.Fatalf("preview error = %v, want cancellation", err)
	}
}

func TestContextReaderStopRetainsStream(t *testing.T) {
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	reader := &contextTestInput{ReadCloser: input, started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	wrapped, stop := ContextReader(ctx, reader)
	stop()
	cancel()
	if got := reader.closes.Load(); got != 0 {
		t.Fatalf("detached cancellation closed the stream %d times", got)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	if got := reader.closes.Load(); got != 1 {
		t.Fatalf("stream closed %d times, want once", got)
	}
}

func TestPreviewDetachesContextFromRetainedStream(t *testing.T) {
	b := NewReader(strings.NewReader("abcdef"), -1, "")
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	preview, err := b.PreviewWithContext(ctx, 2)
	if err != nil || string(preview.Data) != "ab" || !preview.Truncated {
		t.Fatalf("preview = %#v, error = %v; want ab/truncated", preview, err)
	}
	cancel()
	data, err := io.ReadAll(b)
	if err != nil || string(data) != "abcdef" {
		t.Fatalf("retained body = %q, error = %v; want abcdef", data, err)
	}
}

type contextTestInput struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
	closes  atomic.Int32
}

func (r *contextTestInput) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.ReadCloser.Read(p)
}

func (r *contextTestInput) Close() error {
	r.closes.Add(1)
	return r.ReadCloser.Close()
}
