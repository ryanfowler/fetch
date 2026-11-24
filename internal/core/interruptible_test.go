package core

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInterruptibleReaderReadsAllData(t *testing.T) {
	data := strings.Repeat("0123456789", 10000)
	r := NewInterruptibleReader(strings.NewReader(data))
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != data {
		t.Fatalf("read %d bytes, want %d", len(got), len(data))
	}
}

// readBlocked starts a Read on r and returns its result channel after the
// source has been asked for data.
func readBlocked(t *testing.T, r *InterruptibleReader, started <-chan struct{}) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := r.Read(make([]byte, 10))
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("source was not read")
	}
	return done
}

func TestInterruptibleReaderCloseInterruptsBlockedRead(t *testing.T) {
	src := newBlockingSource()
	r := NewInterruptibleReader(src)
	done := readBlocked(t, r, src.started)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read() error = %v, want os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not interrupt a blocked Read")
	}
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read() after Close error = %v, want os.ErrClosed", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
	select {
	case <-src.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not close the source")
	}
}

func TestInterruptibleReaderInterruptsOSPipe(t *testing.T) {
	// Closing an *os.File does not interrupt a blocking pipe read, and it
	// waits for that read. The wrapper must not depend on either.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Close()
	r := NewInterruptibleReader(pr)
	done := make(chan error, 1)
	go func() {
		_, err := r.Read(make([]byte, 10))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	r.Close()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read() error = %v, want os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not interrupt a Read of an idle pipe")
	}
}

func TestInterruptibleReaderDoesNotReadBeforeFirstRead(t *testing.T) {
	src := newBlockingSource()
	r := NewInterruptibleReader(src)
	select {
	case <-src.started:
		t.Fatal("source was read before the first Read")
	case <-time.After(20 * time.Millisecond):
	}
	r.Close()
}

func TestInterruptibleReaderClosesIdleSourceSynchronously(t *testing.T) {
	src := newBlockingSource()
	r := NewInterruptibleReader(src)
	r.Close()
	select {
	case <-src.closed:
	default:
		t.Fatal("Close returned before it closed a source with no read in progress")
	}
}

func TestInterruptibleReaderEmptyReadReturnsAtOnce(t *testing.T) {
	r := NewInterruptibleReader(newBlockingSource())
	defer r.Close()
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = %d, %v; want 0, nil", n, err)
	}
}

func TestInterruptibleReaderReportsSourceWithoutProgress(t *testing.T) {
	src := &emptySource{}
	r := NewInterruptibleReader(src)
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("Read() error = %v, want io.ErrNoProgress", err)
	}
	r.Close()
	reads := src.reads.Load()
	time.Sleep(20 * time.Millisecond)
	if src.reads.Load() != reads {
		t.Fatal("source is still read after the error")
	}
}

func TestInterruptibleReaderReturnsSourceError(t *testing.T) {
	want := errors.New("source failed")
	r := NewInterruptibleReader(io.MultiReader(strings.NewReader("ab"), errReader{want}))
	got, err := io.ReadAll(r)
	if !errors.Is(err, want) || string(got) != "ab" {
		t.Fatalf("ReadAll() = %q, %v; want %q, %v", got, err, "ab", want)
	}
}

// blockingSource blocks every Read until Close.
type blockingSource struct {
	started chan struct{}
	closed  chan struct{}
	once    atomic.Bool
}

func newBlockingSource() *blockingSource {
	return &blockingSource{started: make(chan struct{}), closed: make(chan struct{})}
}

func (s *blockingSource) Read([]byte) (int, error) {
	if s.once.CompareAndSwap(false, true) {
		close(s.started)
	}
	<-s.closed
	return 0, os.ErrClosed
}

func (s *blockingSource) Close() error {
	close(s.closed)
	return nil
}

type emptySource struct{ reads atomic.Int64 }

func (s *emptySource) Read([]byte) (int, error) {
	s.reads.Add(1)
	return 0, nil
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
