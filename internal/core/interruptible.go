package core

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
)

// interruptibleChunkSize is the size of each read from the source.
const interruptibleChunkSize = 32 << 10

// maxEmptyReads is the number of consecutive reads that return no data and
// no error before the source is reported as broken, as bufio does.
const maxEmptyReads = 100

// InterruptibleReader reads from a source whose Read cannot be interrupted,
// such as a pipe on standard input. Go cannot interrupt a blocking pipe read
// by closing the file. InterruptibleReader reads the source on a background
// goroutine, and Close makes a Read that waits for the source return.
//
// The background goroutine starts at the first Read, so the source is not
// consumed before the caller is ready. Close also closes the source, if it
// is an io.Closer. When a source read is in progress, it does so on another
// goroutine, because closing a file waits for a read that is in progress.
// After Close, the background goroutine can stay blocked in the source's
// Read until it returns or the process exits, and data that it reads is
// dropped.
//
// Read and Close are safe to call from different goroutines. Read must not
// be called from more than one goroutine at a time.
type InterruptibleReader struct {
	src       io.Reader
	results   chan interruptibleResult
	done      chan struct{}
	start     sync.Once
	closeOnce sync.Once
	// reading is true while pump may be inside src.Read.
	reading atomic.Bool

	// pending and err are owned by the goroutine that calls Read.
	pending []byte
	err     error
}

type interruptibleResult struct {
	data []byte
	err  error
}

// NewInterruptibleReader returns an InterruptibleReader for src.
func NewInterruptibleReader(src io.Reader) *InterruptibleReader {
	return &InterruptibleReader{
		src:     src,
		results: make(chan interruptibleResult),
		done:    make(chan struct{}),
	}
}

// Read reads data from the source. After Close, it returns os.ErrClosed. A
// Read that runs at the same time as Close can still return data that the
// source has already delivered.
func (r *InterruptibleReader) Read(p []byte) (int, error) {
	select {
	case <-r.done:
		return 0, os.ErrClosed
	default:
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 && r.err == nil {
		r.start.Do(func() { go r.pump() })
		select {
		case result := <-r.results:
			r.pending, r.err = result.data, result.err
		case <-r.done:
			return 0, os.ErrClosed
		}
	}
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	return 0, r.err
}

// Close makes a waiting or later Read return os.ErrClosed, and closes the
// source if it is an io.Closer. It returns the error from closing the source
// when no source read is in progress, and nil otherwise.
func (r *InterruptibleReader) Close() error {
	var err error
	r.closeOnce.Do(func() {
		close(r.done)
		closer, ok := r.src.(io.Closer)
		if !ok {
			return
		}
		// pump sets reading before it checks done. If reading is false
		// here, pump sees done and does not start another read.
		if r.reading.Load() {
			go func() { _ = closer.Close() }()
			return
		}
		err = closer.Close()
	})
	return err
}

// pump reads the source and hands each chunk to Read. It holds at most one
// chunk that Read has not taken.
func (r *InterruptibleReader) pump() {
	empty := 0
	for {
		r.reading.Store(true)
		select {
		case <-r.done:
			r.reading.Store(false)
			return
		default:
		}
		buf := make([]byte, interruptibleChunkSize)
		n, err := r.src.Read(buf)
		r.reading.Store(false)
		if n == 0 && err == nil {
			if empty++; empty < maxEmptyReads {
				continue
			}
			err = io.ErrNoProgress
		}
		empty = 0
		select {
		case r.results <- interruptibleResult{data: buf[:n], err: err}:
		case <-r.done:
			return
		}
		if err != nil {
			return
		}
	}
}
