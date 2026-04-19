package ws

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"

	"github.com/coder/websocket"
)

func TestShouldFormat(t *testing.T) {
	if shouldFormat(core.FormatOff) {
		t.Fatal("FormatOff should return false")
	}
	if !shouldFormat(core.FormatOn) {
		t.Fatal("FormatOn should return true")
	}
}

func TestHandleReadErrNormalClosure(t *testing.T) {
	err := handleReadErr(websocket.CloseError{Code: websocket.StatusNormalClosure})
	if err != nil {
		t.Fatalf("expected nil for normal closure, got: %v", err)
	}
}

func TestHandleReadErrAbnormalClosure(t *testing.T) {
	err := handleReadErr(websocket.CloseError{Code: websocket.StatusInternalError, Reason: "crash"})
	if err == nil {
		t.Fatal("expected error for abnormal closure")
	}
}

func TestHandleReadErrEOF(t *testing.T) {
	err := handleReadErr(io.EOF)
	if err != nil {
		t.Fatalf("expected nil for EOF, got: %v", err)
	}
}

func TestHandleReadErrContextCanceled(t *testing.T) {
	err := handleReadErr(context.Canceled)
	if err != nil {
		t.Fatalf("expected nil for context canceled, got: %v", err)
	}
}

func TestEchoRoundTrip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		for {
			typ, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			conn.Write(r.Context(), typ, data)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	handle := core.NewHandle(core.ColorOff)
	cfg := Config{
		Conn:      conn,
		Stdin:     strings.NewReader("hello\nworld\n"),
		Stderr:    handle.Stderr(),
		Stdout:    handle.Stdout(),
		Format:    core.FormatOff,
		Verbosity: core.VNormal,
	}

	err = Run(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPipedStdinLongMessage(t *testing.T) {
	message := strings.Repeat("x", 70*1024)
	received := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		conn.SetReadLimit(int64(len(message) + 1024))

		_, data, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		received <- append([]byte(nil), data...)
		conn.Write(r.Context(), websocket.MessageText, []byte("ack"))
		conn.Close(websocket.StatusNormalClosure, "done")
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	stdout := core.TestPrinter(false)
	cfg := Config{
		Conn:      conn,
		Stdin:     strings.NewReader(message + "\n"),
		Stderr:    core.TestPrinter(false),
		Stdout:    stdout,
		Format:    core.FormatOff,
		Verbosity: core.VNormal,
	}

	err = Run(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := string(stdout.Bytes())
	want := "ack\n"
	if got != want {
		t.Fatalf("expected ack output %q, got %q", want, got)
	}

	select {
	case data := <-received:
		if string(data) != message {
			t.Fatalf("expected sent message length %d, got %d", len(message), len(data))
		}
	default:
		t.Fatal("server did not receive long stdin message")
	}
}

func TestWriteLoopReturnsStdinReadError(t *testing.T) {
	readErr := errors.New("stdin failed")
	err := writeLoop(context.Background(), Config{Stdin: errReader{err: readErr}})
	if !errors.Is(err, readErr) {
		t.Fatalf("expected stdin read error, got %v", err)
	}
}

func TestInitialMessageEcho(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		// Read the initial message and echo it, then close.
		_, data, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		conn.Write(r.Context(), websocket.MessageText, data)
		conn.Close(websocket.StatusNormalClosure, "done")
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	handle := core.NewHandle(core.ColorOff)
	cfg := Config{
		Conn:       conn,
		Stdin:      nil,
		Stderr:     handle.Stderr(),
		Stdout:     handle.Stdout(),
		Format:     core.FormatOff,
		Verbosity:  core.VNormal,
		InitialMsg: []byte(`hello`),
	}

	err = Run(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

type errReader struct {
	err error
}

func (r errReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestServerCloseNormal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		conn.Write(r.Context(), websocket.MessageText, []byte("bye"))
		conn.Close(websocket.StatusNormalClosure, "done")
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	handle := core.NewHandle(core.ColorOff)
	cfg := Config{
		Conn:      conn,
		Stdin:     nil,
		Stderr:    handle.Stderr(),
		Stdout:    handle.Stdout(),
		Format:    core.FormatOff,
		Verbosity: core.VNormal,
	}

	err = Run(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
