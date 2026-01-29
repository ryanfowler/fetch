package fetch

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestUploadProgressBarRead(t *testing.T) {
	data := []byte("hello world upload test data")
	r := bytes.NewReader(data)

	p := core.NewHandle(core.ColorOff).Stderr()

	pb := newUploadProgressBar(r, p, int64(len(data)))

	buf := make([]byte, 10)
	var total int
	for {
		n, err := pb.Read(buf)
		total += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
	}

	if total != len(data) {
		t.Fatalf("expected %d bytes read, got %d", len(data), total)
	}

	pb.Close(nil)
}

func TestUploadProgressSpinnerRead(t *testing.T) {
	data := []byte("spinner upload data")
	r := bytes.NewReader(data)

	p := core.NewHandle(core.ColorOff).Stderr()

	ps := newUploadProgressSpinner(r, p)

	out, err := io.ReadAll(ps)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if !bytes.Equal(out, data) {
		t.Fatalf("expected %q, got %q", data, out)
	}

	ps.Close(nil)
}

func TestUploadProgressStaticRead(t *testing.T) {
	data := []byte("static upload data")
	r := bytes.NewReader(data)

	p := core.NewHandle(core.ColorOff).Stderr()

	ps := newUploadProgressStatic(r, p)

	out, err := io.ReadAll(ps)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if !bytes.Equal(out, data) {
		t.Fatalf("expected %q, got %q", data, out)
	}

	if ps.bytesRead != int64(len(data)) {
		t.Fatalf("expected bytesRead=%d, got %d", len(data), ps.bytesRead)
	}

	ps.Close(nil)
}

func TestUploadReadCloser(t *testing.T) {
	data := []byte("read closer test")
	r := bytes.NewReader(data)
	closed := false
	closer := closerFunc(func() error {
		closed = true
		return nil
	})

	urc := &uploadReadCloser{Reader: r, closer: closer}

	out, err := io.ReadAll(urc)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if !bytes.Equal(out, data) {
		t.Fatalf("expected %q, got %q", data, out)
	}

	if err := urc.Close(); err != nil {
		t.Fatalf("unexpected close error: %s", err.Error())
	}
	if !closed {
		t.Fatal("expected closer to be called")
	}
}

type closerFunc func() error

func (f closerFunc) Close() error {
	return f()
}

func TestWriteUploadFinalProgress(t *testing.T) {
	p := core.NewHandle(core.ColorOff).Stderr()

	writeUploadFinalProgress(p, 1024, 500*time.Millisecond, -1)

	output := string(p.Bytes())
	if !strings.Contains(output, "Uploaded") {
		t.Fatalf("expected output to contain 'Uploaded', got: %s", output)
	}
	if strings.Contains(output, "Downloaded") {
		t.Fatalf("output should not contain 'Downloaded', got: %s", output)
	}
	if !strings.Contains(output, "1.0KB") {
		t.Fatalf("expected output to contain '1.0KB', got: %s", output)
	}
}

func TestUploadProgressBarCloseWithError(t *testing.T) {
	data := []byte("error test")
	r := bytes.NewReader(data)

	p := core.NewHandle(core.ColorOff).Stderr()

	pb := newUploadProgressBar(r, p, int64(len(data)))

	// Read all data.
	io.ReadAll(pb)

	// Close with an error — should not panic and should not print "Uploaded".
	pb.Close(errors.New("test error"))
}

func TestUploadProgressStaticCloseWithError(t *testing.T) {
	data := []byte("error test static")
	r := bytes.NewReader(data)

	p := core.NewHandle(core.ColorOff).Stderr()

	ps := newUploadProgressStatic(r, p)
	io.ReadAll(ps)

	// Close with error — should produce no output.
	ps.Close(errors.New("test error"))

	output := string(p.Bytes())
	if strings.Contains(output, "Uploaded") {
		t.Fatalf("output should not contain 'Uploaded' on error, got: %s", output)
	}
}
