package multipart

import (
	"bytes"
	"mime"
	"mime/multipart"
	"os"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestMultipart(t *testing.T) {
	tests := []struct {
		name   string
		fnPre  func(*testing.T) ([]core.KeyVal[string], func())
		fnPost func(*testing.T, *multipart.Form)
	}{
		{
			name: "small json file",
			fnPre: func(t *testing.T) ([]core.KeyVal[string], func()) {
				t.Helper()

				f, err := os.CreateTemp("", "*.json")
				if err != nil {
					t.Fatalf("unable to create temp file: %s", err.Error())
				}
				defer f.Close()
				f.WriteString(`{"key":"val"}`)

				return []core.KeyVal[string]{{Key: "key1", Val: "@" + f.Name()}}, func() {
					os.Remove(f.Name())
				}
			},
			fnPost: func(t *testing.T, f *multipart.Form) {
				t.Helper()

				header := f.File["key1"][0]
				if ct := header.Header.Get("Content-Type"); ct != "application/json" {
					t.Fatalf("unexpected content-type: %q", ct)
				}

				file, err := header.Open()
				if err != nil {
					t.Fatalf("unable to open file: %s", err.Error())
				}
				defer file.Close()

				var buf bytes.Buffer
				buf.ReadFrom(file)
				if buf.String() != `{"key":"val"}` {
					t.Fatalf("unexpected file content: %q", buf.String())
				}
			},
		},
		{
			name: "file longer than 512 bytes with no extension",
			fnPre: func(t *testing.T) ([]core.KeyVal[string], func()) {
				t.Helper()

				f, err := os.CreateTemp("", "")
				if err != nil {
					t.Fatalf("unable to create temp file: %s", err.Error())
				}
				defer f.Close()

				f.WriteString("\xFF\xD8\xFF") // JPEG signature.
				f.Write(make([]byte, 512))

				return []core.KeyVal[string]{{Key: "key1", Val: "@" + f.Name()}}, func() {
					os.Remove(f.Name())
				}
			},
			fnPost: func(t *testing.T, f *multipart.Form) {
				t.Helper()

				header := f.File["key1"][0]
				if ct := header.Header.Get("Content-Type"); ct != "image/jpeg" {
					t.Fatalf("unexpected content-type: %q", ct)
				}

				file, err := header.Open()
				if err != nil {
					t.Fatalf("unable to open file: %s", err.Error())
				}
				defer file.Close()

				var buf bytes.Buffer
				buf.ReadFrom(file)

				var exp bytes.Buffer
				exp.WriteString("\xFF\xD8\xFF")
				exp.Write(make([]byte, 512))
				if !bytes.Equal(buf.Bytes(), exp.Bytes()) {
					t.Fatalf("unexpected file content: %q", buf.String())
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, fn := test.fnPre(t)
			if fn != nil {
				defer fn()
			}

			mp := NewMultipart(input)

			var buf bytes.Buffer
			_, err := buf.ReadFrom(mp)
			if err != nil {
				t.Fatalf("unable to read from multipart: %s", err.Error())
			}

			_, params, err := mime.ParseMediaType(mp.ContentType())
			if err != nil {
				t.Fatalf("unable to parse media type: %s", err.Error())
			}

			form, err := multipart.NewReader(&buf, params["boundary"]).ReadForm(1 << 24)
			if err != nil {
				t.Fatalf("unable to read multipart form: %s", err.Error())
			}

			test.fnPost(t, form)
		})
	}
}
