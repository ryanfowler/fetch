package fetch

import (
	"io"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
)

// binaryGuardReader classifies each response chunk before it is returned to
// the output sink. It keeps an incomplete UTF-8 suffix until the next read so
// a rune split at a transport boundary is not mistaken for binary data.
// Once binary data is found, the current chunk is never returned to the sink.
type readerWithCloser struct {
	io.Reader
	closers []io.Closer
}

func newReaderWithCloser(reader io.Reader, closers ...io.Closer) io.ReadCloser {
	return readerWithCloser{Reader: reader, closers: closers}
}

func (r readerWithCloser) Close() error {
	var firstErr error
	for _, closer := range r.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type binaryGuardReader struct {
	source   io.Reader
	drain    bool
	onBinary func()

	pending  []byte
	combined []byte
	readBuf  []byte
	carry    [utf8.UTFMax]byte
	carryLen int

	done        bool
	terminalErr error
	triggered   bool
	drainedErr  error
}

type untrustedResponseReader struct {
	io.Reader
}

func (untrustedResponseReader) untrustedResponse() {}

func (r untrustedResponseReader) Close() error {
	if closer, ok := r.Reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func newUntrustedResponseReader(source io.Reader) io.ReadCloser {
	return untrustedResponseReader{Reader: source}
}

type terminalSafeReader struct {
	source   io.Reader
	pending  []byte
	combined []byte
	readBuf  []byte
	scratch  []byte
	carry    [utf8.UTFMax]byte
	carryLen int

	sourceErr error
	done      bool
}

func (r *terminalSafeReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		if n == len(r.pending) {
			r.pending = nil
			r.scratch = r.scratch[:0]
		} else {
			r.pending = r.pending[n:]
		}
		return n, nil
	}
	if r.done {
		return 0, r.sourceErr
	}

	for {
		if r.carryLen > 0 && r.sourceErr != nil {
			// The source ended with an incomplete UTF-8 sequence. It is
			// invalid text, so let TerminalSafeText escape its bytes.
			complete := r.carry[:r.carryLen]
			r.carryLen = 0
			r.done = true
			return r.writeSafe(p, complete)
		}
		if r.sourceErr != nil {
			r.done = true
			return 0, r.sourceErr
		}

		if cap(r.readBuf) < len(p) {
			r.readBuf = make([]byte, len(p))
		}
		if cap(r.combined) < len(p)+utf8.UTFMax {
			r.combined = make([]byte, len(p)+utf8.UTFMax)
		}
		r.readBuf = r.readBuf[:len(p)]
		r.combined = r.combined[:r.carryLen]
		copy(r.combined, r.carry[:r.carryLen])
		n, err := r.source.Read(r.readBuf)
		if err != nil {
			r.sourceErr = err
		}
		carryLen := r.carryLen
		r.combined = r.combined[:carryLen+n]
		copy(r.combined[carryLen:], r.readBuf[:n])
		combined := r.combined
		r.carryLen = 0
		if len(combined) == 0 {
			if err != nil {
				r.done = true
				return 0, err
			}
			continue
		}

		completeLen, tailLen := splitIncompleteTrailingUTF8Len(combined)
		copy(r.carry[:tailLen], combined[completeLen:])
		r.carryLen = tailLen
		if completeLen == 0 {
			continue
		}
		return r.writeSafe(p, combined[:completeLen])
	}
}

func (r *terminalSafeReader) writeSafe(p, data []byte) (int, error) {
	r.scratch = core.AppendTerminalSafeBytes(r.scratch[:0], data)
	written := copy(p, r.scratch)
	if written < len(r.scratch) {
		r.pending = r.scratch[written:]
	} else {
		r.scratch = r.scratch[:0]
	}
	return written, nil
}

func (r *terminalSafeReader) Close() error {
	if closer, ok := r.source.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func newTerminalSafeReader(source io.Reader) io.ReadCloser {
	return &terminalSafeReader{source: source}
}

func newBinaryGuardReader(source io.Reader, drain bool, onBinary func()) *binaryGuardReader {
	const readSize = 64 * 1024

	return &binaryGuardReader{
		source:   source,
		drain:    drain,
		onBinary: onBinary,
		readBuf:  make([]byte, readSize),
		combined: make([]byte, readSize+utf8.UTFMax),
	}
}

func (r *binaryGuardReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		if len(r.pending) > 0 {
			n := copy(p, r.pending)
			r.pending = r.pending[n:]
			if len(r.pending) == 0 {
				r.pending = nil
			}
			return n, nil
		}
		if r.triggered {
			if r.drainedErr != nil {
				return 0, r.drainedErr
			}
			return 0, io.EOF
		}
		if r.done {
			if r.carryLen > 0 {
				// An incomplete UTF-8 sequence at end of input cannot be
				// completed by a later transport chunk. Do not write it to a
				// terminal as if it were text.
				r.carryLen = 0
				r.triggerBinary()
				return 0, r.drainedError()
			}
			if r.terminalErr != nil {
				err := r.terminalErr
				r.terminalErr = nil
				return 0, err
			}
			return 0, io.EOF
		}

		n, err := r.source.Read(r.readBuf)
		if n > 0 {
			if err != nil && err != io.EOF {
				r.terminalErr = err
			}
			carryLen := r.carryLen
			r.combined = r.combined[:carryLen+n]
			copy(r.combined, r.carry[:carryLen])
			copy(r.combined[carryLen:], r.readBuf[:n])
			combined := r.combined
			r.carryLen = 0

			if !printableBytes(combined) {
				r.triggerBinary()
				return 0, r.drainedError()
			}

			completeLen, tailLen := splitIncompleteTrailingUTF8Len(combined)
			r.pending = combined[:completeLen]
			copy(r.carry[:tailLen], combined[completeLen:])
			r.carryLen = tailLen
		}

		if err != nil {
			r.done = true
			if err != io.EOF {
				r.terminalErr = err
			}
		}
		if n > 0 || err != nil {
			continue
		}
	}
}

func (r *binaryGuardReader) triggerBinary() {
	if r.triggered {
		return
	}
	r.triggered = true
	if r.onBinary != nil {
		r.onBinary()
	}
	if r.drain {
		_, r.drainedErr = io.Copy(io.Discard, r.source)
	}
}

func (r *binaryGuardReader) drainedError() error {
	if r.drainedErr != nil {
		return r.drainedErr
	}
	if r.terminalErr != nil {
		return r.terminalErr
	}
	return io.EOF
}

func (r *binaryGuardReader) Triggered() bool { return r.triggered }

func (r *binaryGuardReader) Close() error {
	if closer, ok := r.source.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// closeReaderOnContext prevents a canceled pager/output consumer from
// leaving a response-body read blocked. It is intentionally installed only
// for closable sources, so ordinary in-memory readers do not create a
// needless goroutine.
func closeReaderOnContext(ctx interface{ Done() <-chan struct{} }, source io.Reader) func() {
	closer, ok := source.(io.Closer)
	if !ok || ctx.Done() == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = closer.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

func splitIncompleteTrailingUTF8Len(data []byte) (completeLen, tailLen int) {
	maxTail := 4
	if len(data) < maxTail {
		maxTail = len(data)
	}
	for tailLen := 1; tailLen <= maxTail; tailLen++ {
		split := len(data) - tailLen
		tail := data[split:]
		if len(tail) == 0 || !isUTF8LeadingByte(tail[0]) {
			continue
		}
		if !utf8.FullRune(tail) {
			return split, tailLen
		}
	}
	return len(data), 0
}

func isUTF8LeadingByte(b byte) bool {
	return b >= 0xc2 && b <= 0xf4
}

// printableBytes applies the terminal binary heuristic to one complete
// classification window. NUL is always binary. An incomplete final rune is
// deferred to the next window by the stream reader.
func printableBytes(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return false
		}
	}

	maxUnsafe := len(data) / 10
	if maxUnsafe < 1 {
		maxUnsafe = 1
	}
	var safe, total int
	remaining := data
	for len(remaining) > 0 {
		if !utf8.FullRune(remaining) {
			break
		}
		r, size := utf8.DecodeRune(remaining)
		remaining = remaining[size:]
		total++
		if r != utf8.RuneError || size > 1 {
			if r == '\x1b' || !runeIsUnsafe(r) {
				safe++
			}
		} else if total-safe > maxUnsafe {
			return false
		}
	}
	return total == 0 || float64(safe)/float64(total) >= 0.9
}

func runeIsUnsafe(r rune) bool {
	return r < 0x20 && r != '\n' && r != '\t' || (r >= 0x7f && r <= 0x9f) || r == utf8.RuneError
}
