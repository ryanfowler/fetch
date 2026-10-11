package aws

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/body"
)

func TestSignCancelsPayloadReads(t *testing.T) {
	for _, path := range []string{"replayable source", "GetBody", "one-shot fallback", "seekable fallback"} {
		t.Run(path, func(t *testing.T) {
			input, writer := io.Pipe()
			defer input.Close()
			defer writer.Close()
			reader := &signingPipe{PipeReader: input, started: make(chan struct{})}
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			switch path {
			case "replayable source":
				body.Attach(req, body.NewFactory(func() (io.ReadCloser, error) { return reader, nil }, -1, "", true))
			case "GetBody":
				req.Body = io.NopCloser(reader)
				req.GetBody = func() (io.ReadCloser, error) { return reader, nil }
			case "one-shot fallback":
				req.Body = reader
			case "seekable fallback":
				req.Body = &signingSeeker{signingPipe: reader}
			}
			result := make(chan error, 1)
			go func() {
				result <- Sign(req, Config{AccessKey: "key", SecretKey: "secret", Region: "us-east-1", Service: "execute-api"}, time.Now())
			}()
			select {
			case <-reader.started:
			case err := <-result:
				t.Fatalf("Sign returned without reading the payload: %v", err)
			case <-time.After(2 * time.Second):
				t.Fatal("Sign did not start reading")
			}
			cause := errors.New("cancel signing")
			cancel(cause)
			select {
			case err := <-result:
				if !errors.Is(err, cause) {
					t.Fatalf("Sign error = %v, want cancellation cause", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Sign remained blocked after cancellation")
			}
		})
	}
}

type signingPipe struct {
	*io.PipeReader
	started chan struct{}
	once    sync.Once
}

func (r *signingPipe) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.PipeReader.Read(p)
}

type signingSeeker struct{ *signingPipe }

func (*signingSeeker) Seek(int64, int) (int64, error) { return 0, nil }
