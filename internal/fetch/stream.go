package fetch

import (
	"io"
	"unicode/utf8"
)

// binaryGuardReader classifies each response chunk before it is returned to
// the output sink. It keeps an incomplete UTF-8 suffix until the next read so
// a rune split at a transport boundary is not mistaken for binary data.
// Once binary data is found, the current chunk is never returned to the sink.
type binaryGuardReader struct {
	source   io.Reader
	drain    bool
	onBinary func()

	pending []byte
	carry   []byte
	readBuf []byte

	done        bool
	terminalErr error
	triggered   bool
	drainedErr  error
}

func newBinaryGuardReader(source io.Reader, drain bool, onBinary func()) *binaryGuardReader {
	return &binaryGuardReader{
		source:   source,
		drain:    drain,
		onBinary: onBinary,
		readBuf:  make([]byte, 64*1024),
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
			return n, nil
		}
		if r.triggered {
			if r.drainedErr != nil {
				return 0, r.drainedErr
			}
			return 0, io.EOF
		}
		if r.done {
			if len(r.carry) > 0 {
				// An incomplete UTF-8 sequence at end of input cannot be
				// completed by a later transport chunk. Do not write it to a
				// terminal as if it were text.
				r.carry = nil
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
			combined := make([]byte, 0, len(r.carry)+n)
			combined = append(combined, r.carry...)
			combined = append(combined, r.readBuf[:n]...)
			r.carry = nil

			if !printableBytes(combined) {
				r.triggerBinary()
				return 0, r.drainedError()
			}

			complete, tail := splitIncompleteTrailingUTF8(combined)
			r.pending = complete
			r.carry = tail
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

// splitIncompleteTrailingUTF8 returns a complete prefix and a trailing UTF-8
// sequence that needs more bytes. Invalid bytes are not treated as a suffix;
// printableBytes has already classified them as unsafe.
func splitIncompleteTrailingUTF8(data []byte) ([]byte, []byte) {
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
			return data[:split], tail
		}
	}
	return data, nil
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
