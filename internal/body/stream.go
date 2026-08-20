package body

import "io"

// Stream is a single-read response pipeline. Tee writers observe the bytes
// as they pass through; consumers never need to reread the response body.
// AddTee must be called before concurrent reads begin.
type Stream struct {
	source io.ReadCloser
	tees   []io.Writer
}

func NewStream(source io.ReadCloser) *Stream {
	return &Stream{source: source}
}

// AddTee adds a synchronous observer. A writer error is returned to the
// consumer, while the source remains closed by Stream.Close.
func (s *Stream) AddTee(w io.Writer) {
	if w != nil {
		s.tees = append(s.tees, w)
	}
}

func (s *Stream) Read(p []byte) (int, error) {
	n, readErr := s.source.Read(p)
	for _, tee := range s.tees {
		if n == 0 {
			break
		}
		written, err := tee.Write(p[:n])
		if err != nil {
			return n, err
		}
		if written != n {
			return n, io.ErrShortWrite
		}
	}
	return n, readErr
}

func (s *Stream) Close() error { return s.source.Close() }
