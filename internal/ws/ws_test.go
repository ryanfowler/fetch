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
	"sync"
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

func TestPipedStdinDrainsMessagesBeforeClose(t *testing.T) {
	ready := make(chan struct{})
	pingSeen := make(chan struct{})
	serverClose := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			OnPingReceived: func(context.Context, []byte) bool {
				close(pingSeen)
				return true
			},
		})
		if err != nil {
			return
		}
		defer conn.CloseNow()

		messages := make([]struct {
			typ  websocket.MessageType
			data []byte
		}, 2)
		for i := range messages {
			messages[i].typ, messages[i].data, err = conn.Read(r.Context())
			if err != nil {
				return
			}
		}
		close(ready)
		// Keep a reader active so the drain ping can complete. Send the
		// responses first, then use a second ping/pong exchange as an
		// explicit barrier proving the client processed those responses.
		controlDone := make(chan error, 1)
		go func() {
			_, _, err := conn.Read(r.Context())
			controlDone <- err
		}()
		select {
		case <-pingSeen:
		case <-r.Context().Done():
			return
		}
		for _, message := range messages {
			if err := conn.Write(r.Context(), message.typ, message.data); err != nil {
				return
			}
		}
		if err := conn.Ping(r.Context()); err != nil {
			return
		}
		serverClose <- <-controlDone
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	stdout := core.TestPrinter(false)
	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, Config{
			Conn:   conn,
			Stdin:  strings.NewReader("line1\nline2\n"),
			Stderr: core.TestPrinter(false),
			Stdout: stdout,
			Format: core.FormatOff,
		})
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("server did not receive piped messages")
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not finish after draining piped messages")
	}
	select {
	case err := <-serverClose:
		if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
			t.Fatalf("server close error = %v, want normal close", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive the normal close handshake")
	}

	if got := string(stdout.Bytes()); got != "line1\nline2\n" {
		t.Fatalf("stdout = %q, want both echoed messages", got)
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

func TestWriteMessageReturnsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := writeMessage(ctx, nil, websocket.MessageText, []byte("message"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("writeMessage() error = %v, want context.Canceled", err)
	}
}

func TestWriteLoopsStopOnContextCancellation(t *testing.T) {
	for _, mode := range []core.WSMessageMode{core.WSMessageText, core.WSMessageBinary} {
		t.Run(mode.String(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			err := writeLoop(ctx, Config{
				Stdin:       strings.NewReader("message\n"),
				MessageMode: mode,
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("writeLoop() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestCancellationClosesAndJoinsClosableStdin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	input := &blockingReadCloser{blockingReader: newBlockingReader()}
	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, Config{
			Conn:   conn,
			Stdin:  input,
			Stderr: core.TestPrinter(false),
			Stdout: core.TestPrinter(false),
		})
	}()

	select {
	case <-input.started:
	case <-time.After(time.Second):
		t.Fatal("writer did not start reading stdin")
	}
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not join the closable stdin writer")
	}
	select {
	case <-input.done:
	default:
		t.Fatal("closable stdin Read was not released before Run returned")
	}
}

func TestCancellationWaitsForBlockingNonClosableStdin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	input := newBlockingReader()
	defer input.unblock()
	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, Config{
			Conn:   conn,
			Stdin:  input,
			Stderr: core.TestPrinter(false),
			Stdout: core.TestPrinter(false),
		})
	}()

	select {
	case <-input.started:
	case <-time.After(time.Second):
		t.Fatal("writer did not start reading stdin")
	}
	cancel()
	select {
	case err := <-runDone:
		t.Fatalf("Run() returned %v while non-closable stdin was blocked", err)
	case <-time.After(100 * time.Millisecond):
	}

	input.unblock()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not finish after the non-closable stdin returned")
	}
	select {
	case <-input.done:
	default:
		t.Fatal("non-closable stdin Read did not return before Run finished")
	}
}

func TestWriterErrorJoinsReadLoop(t *testing.T) {
	output := newBlockingWriter()
	defer output.unblock()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		if err := conn.Write(r.Context(), websocket.MessageText, []byte("message")); err != nil {
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	input := newDelayedReadError(errors.New("stdin failed"))
	stdout := core.TestPrinter(false).NewWriter(output)
	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, Config{
			Conn:   conn,
			Stdin:  input,
			Stderr: core.TestPrinter(false),
			Stdout: stdout,
		})
	}()

	select {
	case <-output.started:
	case <-time.After(time.Second):
		t.Fatal("readLoop did not block in stdout")
	}
	input.unblock()

	select {
	case err := <-runDone:
		output.unblock()
		t.Fatalf("Run() returned before joining readLoop: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	output.unblock()
	select {
	case err := <-runDone:
		if !errors.Is(err, input.err) {
			t.Fatalf("Run() error = %v, want stdin error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not finish after stdout was released")
	}
}

func TestCloseCompletionTimeoutJoinsReadLoop(t *testing.T) {
	output, closeReceived, runDone, cleanup := startBlockedCloseSession(t)
	defer cleanup.close()

	select {
	case <-closeReceived:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive the close handshake")
	}

	select {
	case err := <-runDone:
		output.unblock()
		t.Fatalf("Run() returned before joining readLoop: %v", err)
	case <-time.After(1100 * time.Millisecond):
	}

	output.unblock()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not finish after stdout was released")
	}
}

func TestCloseCancellationJoinsReadLoop(t *testing.T) {
	output, closeReceived, runDone, cleanup := startBlockedCloseSession(t)
	defer cleanup.close()

	select {
	case <-closeReceived:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive the close handshake")
	}
	cleanup.cancel()

	select {
	case err := <-runDone:
		output.unblock()
		t.Fatalf("Run() returned before joining readLoop: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	output.unblock()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not finish after stdout was released")
	}
}

func TestRunWaitsForPendingCloseHandshake(t *testing.T) {
	readErr := errors.New("stdout failed")
	output := newBlockingErrorWriter(readErr)
	serverReady := make(chan struct{})
	serverStop := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		if _, _, err := conn.Read(r.Context()); err != nil {
			return
		}
		if err := conn.Write(r.Context(), websocket.MessageText, []byte("message")); err != nil {
			return
		}
		close(serverReady)
		<-serverStop
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	var stopServer sync.Once
	defer func() {
		stopServer.Do(func() { close(serverStop) })
		conn.CloseNow()
	}()

	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, Config{
			Conn:   conn,
			Stdin:  strings.NewReader("payload\n"),
			Stderr: core.TestPrinter(false),
			Stdout: core.TestPrinter(false).NewWriter(output),
		})
	}()

	select {
	case <-output.started:
	case <-time.After(time.Second):
		conn.CloseNow()
		t.Fatal("readLoop did not start writing output")
	}
	select {
	case <-serverReady:
	case <-time.After(time.Second):
		conn.CloseNow()
		t.Fatal("server did not send the pending output")
	}

	// The drain period is one second and starting Conn.Close has an additional
	// short delay. Let both complete while readLoop still owns the read lock.
	time.Sleep(1200 * time.Millisecond)
	output.unblock()

	select {
	case err := <-runDone:
		t.Fatalf("Run() returned before pending Conn.Close completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	stopServer.Do(func() { close(serverStop) })
	select {
	case err := <-runDone:
		if !errors.Is(err, readErr) {
			t.Fatalf("Run() error = %v, want stdout error", err)
		}
	case <-time.After(2 * time.Second):
		conn.CloseNow()
		t.Fatal("Run() did not finish after pending close handshake was released")
	}
}

type blockedCloseSession struct {
	cancel context.CancelFunc
	stop   func()
}

func (s *blockedCloseSession) close() {
	s.stop()
}

func startBlockedCloseSession(t *testing.T) (*blockingWriter, <-chan struct{}, <-chan error, *blockedCloseSession) {
	t.Helper()

	output := newBlockingWriter()
	closeReceived := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		if _, _, err := conn.Read(r.Context()); err != nil {
			return
		}
		if err := conn.Write(r.Context(), websocket.MessageText, []byte("message")); err != nil {
			return
		}
		_, _, _ = conn.Read(r.Context())
		close(closeReceived)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, _, err := websocket.Dial(ctx, server.URL, nil)
	if err != nil {
		cancel()
		server.Close()
		t.Fatal(err)
	}

	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, Config{
			Conn:   conn,
			Stdin:  strings.NewReader("payload\n"),
			Stderr: core.TestPrinter(false),
			Stdout: core.TestPrinter(false).NewWriter(output),
		})
	}()

	cleanup := &blockedCloseSession{cancel: cancel}
	cleanup.stop = func() {
		output.unblock()
		cancel()
		conn.CloseNow()
		server.Close()
	}
	return output, closeReceived, runDone, cleanup
}

type blockingReader struct {
	started    chan struct{}
	release    chan struct{}
	done       chan struct{}
	releaseOne sync.Once
	doneOnce   sync.Once
}

func newBlockingReader() *blockingReader {
	return &blockingReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
		done:    make(chan struct{}),
	}
}

func (r *blockingReader) Read([]byte) (int, error) {
	close(r.started)
	<-r.release
	r.doneOnce.Do(func() { close(r.done) })
	return 0, io.EOF
}

func (r *blockingReader) unblock() {
	r.releaseOne.Do(func() { close(r.release) })
}

type blockingReadCloser struct {
	*blockingReader
}

func (r *blockingReadCloser) Close() error {
	r.unblock()
	return nil
}

type delayedReadError struct {
	err        error
	started    chan struct{}
	release    chan struct{}
	startOnce  sync.Once
	releaseOne sync.Once
}

func newDelayedReadError(err error) *delayedReadError {
	return &delayedReadError{
		err:     err,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (r *delayedReadError) Read([]byte) (int, error) {
	r.startOnce.Do(func() { close(r.started) })
	<-r.release
	return 0, r.err
}

func (r *delayedReadError) unblock() {
	r.releaseOne.Do(func() { close(r.release) })
}

type blockingWriter struct {
	started    chan struct{}
	release    chan struct{}
	done       chan struct{}
	startOnce  sync.Once
	releaseOne sync.Once
	doneOnce   sync.Once
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{
		started: make(chan struct{}),
		release: make(chan struct{}),
		done:    make(chan struct{}),
	}
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.startOnce.Do(func() { close(w.started) })
	<-w.release
	w.doneOnce.Do(func() { close(w.done) })
	return len(p), nil
}

func (w *blockingWriter) Close() error {
	w.unblock()
	return nil
}

func (w *blockingWriter) unblock() {
	w.releaseOne.Do(func() { close(w.release) })
}

type blockingErrorWriter struct {
	err        error
	started    chan struct{}
	release    chan struct{}
	releaseOne sync.Once
}

func newBlockingErrorWriter(err error) *blockingErrorWriter {
	return &blockingErrorWriter{
		err:     err,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (w *blockingErrorWriter) Write([]byte) (int, error) {
	close(w.started)
	<-w.release
	return 0, w.err
}

func (w *blockingErrorWriter) unblock() {
	w.releaseOne.Do(func() { close(w.release) })
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
