package cli

import (
	"io"
	"os"

	"github.com/ryanfowler/fetch/internal/body"
	"github.com/ryanfowler/fetch/internal/curl"
)

// streamingCurlBody keeps single-file uploads lazy and replayable. Textual
// file data has unknown output length because curl drops CR, LF, and NUL.
func streamingCurlBody(value curl.DataValue) (io.Reader, error) {
	reader, _, err := RequestBody(value.Value)
	if err != nil {
		return nil, err
	}
	if value.Kind != curl.DataText {
		return reader, nil
	}
	var source *body.Body
	if value.Value == "@-" {
		source = body.NewReader(reader, -1, "")
	} else {
		source, err = body.NewFileFromOpenFile(reader.(*os.File), "")
		if err != nil {
			return nil, err
		}
	}
	return body.NewFactory(func() (io.ReadCloser, error) {
		var rc io.ReadCloser
		var err error
		if source.Replayable() {
			rc, err = source.Replay()
		} else {
			rc, err = source.Open()
		}
		if err != nil {
			return nil, err
		}
		return &curlTextReader{ReadCloser: rc}, nil
	}, -1, "", source.Replayable()), nil
}

type curlTextReader struct{ io.ReadCloser }

func (r *curlTextReader) Read(p []byte) (int, error) {
	for {
		n, err := r.ReadCloser.Read(p)
		kept := 0
		for _, b := range p[:n] {
			if b != '\r' && b != '\n' && b != 0 {
				p[kept] = b
				kept++
			}
		}
		if kept > 0 || err != nil || n == 0 {
			return kept, err
		}
	}
}
