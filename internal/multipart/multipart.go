package multipart

import (
	"io"
	"mime/multipart"
	"net/textproto"
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
func NewMultipart(kvs []core.KeyVal[string]) *Multipart {
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
			err := writeFilePart(mpw, kv.Key, kv.Val[1:])
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
	headers.Set("Content-Disposition", multipart.FileContentDisposition(key, filename))
	headers.Set("Content-Type", ct)

	w, err := mpw.CreatePart(headers)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, r)
	return err
}
