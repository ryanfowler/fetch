package multipart

import (
	"io"
	"mime/multipart"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

// Multipart builds replayable multipart request bodies.
type Multipart struct {
	fields      []core.KeyVal[string]
	boundary    string
	contentType string
}

// NewMultipart returns a Multipart using the provided key/values.
func NewMultipart(kvs []core.KeyVal[string]) *Multipart {
	if len(kvs) == 0 {
		return nil
	}

	mpw := multipart.NewWriter(io.Discard)
	fields := append([]core.KeyVal[string](nil), kvs...)
	boundary := mpw.Boundary()

	return &Multipart{
		fields:      fields,
		boundary:    boundary,
		contentType: mpw.FormDataContentType(),
	}
}

// Open returns a fresh multipart request body stream.
func (m *Multipart) Open() (io.ReadCloser, error) {
	// Create a pipe and asynchronously write to it in a goroutine.
	reader, writer := io.Pipe()
	mpw := multipart.NewWriter(writer)
	if err := mpw.SetBoundary(m.boundary); err != nil {
		_ = reader.CloseWithError(err)
		_ = writer.CloseWithError(err)
		return nil, err
	}

	go func() {
		var err error
		defer func() {
			if err != nil {
				_ = writer.CloseWithError(err)
				return
			}
			if err = mpw.Close(); err != nil {
				_ = writer.CloseWithError(err)
				return
			}
			_ = writer.Close()
		}()

		for _, kv := range m.fields {
			if !strings.HasPrefix(kv.Val, "@") {
				if err = mpw.WriteField(kv.Key, kv.Val); err != nil {
					return
				}
				continue
			}

			// Form part is a file.
			if err = writeFilePart(mpw, kv.Key, kv.Val[1:]); err != nil {
				return
			}
		}
	}()

	return reader, nil
}

// ContentType returns the Content-Type header value to use for this request.
func (m *Multipart) ContentType() string {
	return m.contentType
}

// writes the multipart file part and returns any error encountered.
func writeFilePart(mpw *multipart.Writer, key, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	r, ct, err := core.DetectContentType(f, filename)
	if err != nil {
		return err
	}

	headers := textproto.MIMEHeader{}
	headers.Set("Content-Disposition", multipart.FileContentDisposition(key, filepath.Base(filename)))
	headers.Set("Content-Type", ct)

	w, err := mpw.CreatePart(headers)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, r)
	return err
}
