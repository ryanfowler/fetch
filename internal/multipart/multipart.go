package multipart

import (
	"io"
	"mime/multipart"
	"os"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

// Multipart implements io.Reader for multipart data.
type Multipart struct {
	io.Reader
	contentType string
}

// NewMultipart returns a Multipart using the provided key/values.
func NewMultipart(kvs []core.KeyVal) *Multipart {
	if len(kvs) == 0 {
		return nil
	}

	// Create a pipe and asynchronously write to it in a goroutine.
	reader, writer := io.Pipe()
	mpw := multipart.NewWriter(writer)
	go func() {
		defer func() {
			mpw.Close()
			writer.Close()
		}()

		for _, kv := range kvs {
			if !strings.HasPrefix(kv.Val, "@") {
				err := mpw.WriteField(kv.Key, kv.Val)
				if err != nil {
					writer.CloseWithError(err)
					return
				}
				continue
			}

			// Form part is a file.
			w, err := mpw.CreateFormFile(kv.Key, kv.Val[1:])
			if err != nil {
				writer.CloseWithError(err)
				return
			}

			f, err := os.Open(kv.Val[1:])
			if err != nil {
				writer.CloseWithError(err)
				return
			}

			_, err = io.Copy(w, f)
			f.Close()
			if err != nil {
				writer.CloseWithError(err)
				return
			}
		}
	}()

	return &Multipart{
		Reader:      reader,
		contentType: mpw.FormDataContentType(),
	}
}

// ContentType returns the Content-Type header value to use for this request.
func (m *Multipart) ContentType() string {
	return m.contentType
}
