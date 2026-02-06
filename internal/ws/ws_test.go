package ws

import (
	"context"
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
