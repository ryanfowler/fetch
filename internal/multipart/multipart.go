package multipart

import (
	"io"
	"mime/multipart"
	"os"
	"strings"

	"github.com/ryanfowler/fetch/internal/vars"
)

type Multipart struct {
	io.Reader
	contentType string
}

func NewMultipart(kvs []vars.KeyVal) *Multipart {
	if len(kvs) == 0 {
		return nil
	}

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

func (m *Multipart) ContentType() string {
	return m.contentType
}
