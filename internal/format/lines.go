package format

import (
	"errors"
	"fmt"
	"io"

	"github.com/ryanfowler/fetch/internal/core"
)

// maxStreamingRecordBytes bounds one NDJSON record or complete SSE event. A
// stream stays incremental, but a malformed peer must not be able to grow a
// pending record without limit.
const maxStreamingRecordBytes = core.MaxStreamingRecordBytes

// lineReader splits a stream on LF, CRLF, or CR. It scans each newly read
// chunk once and keeps only the current pending line. In particular, it does
// not append one byte at a time for a long record.
type lineReader struct {
	r           io.Reader
	pending     []byte
	scan        int
	eof         bool
	endingBytes int
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: r}
}

// next returns the next line without its line ending. It returns ok=false only
// after the input is exhausted and no bytes remain.
func (r *lineReader) next() (line []byte, ok bool, err error) {
	for {
		if i := r.findLineEnd(); i >= 0 {
			if int64(i) > maxStreamingRecordBytes {
				return nil, false, fmt.Errorf("stream record exceeds %d-byte limit: %w", maxStreamingRecordBytes, ErrStreamingLimit)
			}
			end := i + 1
			if r.pending[i] == '\r' {
				if i+1 == len(r.pending) && !r.eof {
					// A CR at the end of a chunk may be the first half of
					// CRLF. Wait for the next chunk before returning it.
					r.scan = i
				} else {
					if i+1 < len(r.pending) && r.pending[i+1] == '\n' {
						end++
					}
					return r.takeLine(i, end), true, nil
				}
			} else {
				return r.takeLine(i, end), true, nil
			}
		}

		if int64(len(r.pending)) > maxStreamingRecordBytes {
			return nil, false, fmt.Errorf("stream record exceeds %d-byte limit: %w", maxStreamingRecordBytes, ErrStreamingLimit)
		}
		if r.eof {
			if len(r.pending) == 0 {
				return nil, false, nil
			}
			line := r.pending
			r.pending = nil
			r.scan = 0
			r.endingBytes = 0
			return line, true, nil
		}

		chunk := make([]byte, 32*1024)
		n, readErr := r.r.Read(chunk)
		if n > 0 {
			r.pending = append(r.pending, chunk[:n]...)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				r.eof = true
				continue
			}
			return nil, false, readErr
		}
		if n == 0 {
			return nil, false, io.ErrNoProgress
		}
	}
}

func (r *lineReader) findLineEnd() int {
	if r.scan >= len(r.pending) {
		return -1
	}
	i := r.scan
	for i < len(r.pending) {
		if r.pending[i] == '\n' || r.pending[i] == '\r' {
			r.scan = i
			return i
		}
		i++
	}
	r.scan = len(r.pending)
	return -1
}

func (r *lineReader) takeLine(end, advance int) []byte {
	line := r.pending[:end]
	r.endingBytes = advance - end
	// Return a view for the callback, then retain only unread bytes. The
	// callback must finish using line before the next call to next.
	r.pending = r.pending[advance:]
	r.scan = 0
	return line
}

func (r *lineReader) lineEndingBytes() int { return r.endingBytes }

var ErrStreamingLimit = errors.New("streaming record limit exceeded")

func formatStreamingError(kind string, line int, err error) error {
	return fmt.Errorf("invalid %s record at line %d: %w", kind, line, err)
}
