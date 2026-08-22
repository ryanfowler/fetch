package ws

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"

	"github.com/coder/websocket"
)

func TestBinaryMessagesAreRawWhenStdoutIsNotTerminal(t *testing.T) {
	stdout := core.TestPrinter(false)
	stderr := core.TestPrinter(false)
	data := []byte{0x00, 0xff, 'x'}
	if err := writeBinaryMessageForTerminal(data, Config{Stdout: stdout, Stderr: stderr}, false); err != nil {
		t.Fatal(err)
	}
	if got := stdout.Bytes(); !reflect.DeepEqual(got, data) {
		t.Fatalf("stdout = %v, want %v", got, data)
	}
	if len(stderr.Bytes()) != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.Bytes())
	}
}

func TestBinaryMessagesNeverReachTerminalStdout(t *testing.T) {
	stdout := core.TestPrinter(false)
	stderr := core.TestPrinter(false)
	data := []byte{0x00, 0xff, 'x'}
	if err := writeBinaryMessageForTerminal(data, Config{Stdout: stdout, Stderr: stderr}, true); err != nil {
		t.Fatal(err)
	}
	if len(stdout.Bytes()) != 0 {
		t.Fatalf("stdout = %v, want empty", stdout.Bytes())
	}
	if got := string(stderr.Bytes()); got != "[binary 3 bytes]\n" {
		t.Fatalf("stderr = %q, want binary indicator", got)
	}
}

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

func TestInitialMessageMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    core.WSMessageMode
		data    []byte
		want    websocket.MessageType
		wantErr bool
	}{
		{name: "auto text", mode: core.WSMessageAuto, data: []byte("hello"), want: websocket.MessageText},
		{name: "auto binary", mode: core.WSMessageAuto, data: []byte{0xff}, want: websocket.MessageBinary},
		{name: "forced text", mode: core.WSMessageText, data: []byte("hello"), want: websocket.MessageText},
		{name: "forced text rejects invalid UTF-8", mode: core.WSMessageText, data: []byte{0xff}, wantErr: true},
		{name: "forced binary", mode: core.WSMessageBinary, data: []byte("hello"), want: websocket.MessageBinary},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := initialMessageType(tt.mode, tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("initialMessageType() error = %v, want error %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("initialMessageType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadBoundedLinePreservesEmptyAndCRLF(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("one\n\r\ntwo\r\nfour"))
	var got []string
	for {
		line, ok, err := readBoundedLine(reader, 16)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		got = append(got, string(line))
	}
	want := []string{"one", "", "two", "four"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %#v, want %#v", got, want)
	}
}

func TestReadBoundedLineRejectsOverflow(t *testing.T) {
	_, _, err := readBoundedLine(bufio.NewReader(strings.NewReader(strings.Repeat("x", int(core.MaxWebSocketPipedTextLine)+1))), core.MaxWebSocketPipedTextLine)
	if !errors.Is(err, core.ErrLimitExceeded) {
		t.Fatalf("error = %v, want limit error", err)
	}
}

func TestServerReceivesBinaryPipedInput(t *testing.T) {
	received := make(chan struct {
		typ  websocket.MessageType
		data []byte
	}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		typ, data, err := conn.Read(r.Context())
		if err == nil {
			received <- struct {
				typ  websocket.MessageType
				data []byte
			}{typ, append([]byte(nil), data...)}
		}
		conn.Close(websocket.StatusNormalClosure, "done")
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Conn:        conn,
		Stdin:       strings.NewReader("a\n\x00b"),
		MessageMode: core.WSMessageBinary,
		Stderr:      core.TestPrinter(false),
		Stdout:      core.TestPrinter(false),
	}
	if err := Run(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got.typ != websocket.MessageBinary || string(got.data) != "a\n\x00b" {
			t.Fatalf("received = (%v, %q), want binary payload", got.typ, got.data)
		}
	default:
		t.Fatal("server did not receive binary input")
	}
}

func TestServerReceivesEmptyTextLine(t *testing.T) {
	received := make(chan [][]byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		messages := make([][]byte, 0, 2)
		for range 2 {
			_, data, readErr := conn.Read(r.Context())
			if readErr != nil {
				return
			}
			messages = append(messages, append([]byte(nil), data...))
		}
		received <- messages
		conn.Close(websocket.StatusNormalClosure, "done")
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Conn:   conn,
		Stdin:  strings.NewReader("first\n\n"),
		Stderr: core.TestPrinter(false),
		Stdout: core.TestPrinter(false),
	}
	if err := Run(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	select {
	case messages := <-received:
		if len(messages) != 2 || string(messages[0]) != "first" || len(messages[1]) != 0 {
			t.Fatalf("messages = %#v, want first and empty", messages)
		}
	default:
		t.Fatal("server did not receive both text lines")
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

func TestIncomingMessageLimitIsEnforced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		_ = conn.Write(r.Context(), websocket.MessageBinary, make([]byte, int(core.MaxWebSocketMessageBytes)+1))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = Run(ctx, Config{
		Conn:   conn,
		Stderr: core.TestPrinter(false),
		Stdout: core.TestPrinter(false),
	})
	if !errors.Is(err, websocket.ErrMessageTooBig) {
		t.Fatalf("error = %v, want ErrMessageTooBig", err)
	}
}

func TestPipedEOFPerformsCloseHandshake(t *testing.T) {
	closed := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			closed <- err
			return
		}
		defer conn.CloseNow()
		if _, _, err := conn.Read(r.Context()); err != nil {
			closed <- err
			return
		}
		_, _, err = conn.Read(r.Context())
		closed <- err
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, Config{
		Conn:   conn,
		Stdin:  strings.NewReader("payload\n"),
		Stderr: core.TestPrinter(false),
		Stdout: core.TestPrinter(false),
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	select {
	case err := <-closed:
		if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
			t.Fatalf("server close error = %v, want normal close", err)
		}
	case <-ctx.Done():
		t.Fatal("server did not receive the close handshake")
	}
}

func TestMessageQueueUsesByteBudget(t *testing.T) {
	q := newMessageQueue()
	payload := make([]byte, int(core.MaxWebSocketMessageBytes))
	if err := q.push(context.Background(), wsMessage{typ: websocket.MessageBinary, data: payload}); err != nil {
		t.Fatal(err)
	}
	if err := q.push(context.Background(), wsMessage{typ: websocket.MessageBinary, data: payload}); err != nil {
		t.Fatal(err)
	}
	if got := q.bytes(); got > interactiveQueueBytes {
		t.Fatalf("queue bytes = %d, want <= %d", got, interactiveQueueBytes)
	}
	q.pop()
	q.pop()
	if got := q.bytes(); got != 0 {
		t.Fatalf("queue bytes after pop = %d, want 0", got)
	}
}
