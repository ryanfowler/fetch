package ws

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// blockableConn is a client connection whose writes block while block is
// set, until the connection is closed. It makes a peer that does not read
// deterministic, without depending on socket buffer sizes.
type blockableConn struct {
	net.Conn
	block     atomic.Bool
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *blockableConn) Write(p []byte) (int, error) {
	if c.block.Load() {
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}

func (c *blockableConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// dialBlockable returns a WebSocket connection to a server that echoes
// messages, and the client network connection under it.
func dialBlockable(t *testing.T, ctx context.Context) (*websocket.Conn, *blockableConn) {
	t.Helper()
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
			_ = conn.Write(r.Context(), typ, data)
		}
	}))
	t.Cleanup(server.Close)

	var clientConn *blockableConn
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			clientConn = &blockableConn{Conn: conn, closed: make(chan struct{})}
			return clientConn, nil
		},
	}
	conn, _, err := websocket.Dial(ctx, server.URL, &websocket.DialOptions{HTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn, clientConn
}

func newTestInteractiveMode(conn *websocket.Conn, cancel context.CancelFunc) *interactiveMode {
	return &interactiveMode{
		cfg:      Config{Conn: conn},
		term:     &terminal{rows: 24, cols: 80},
		rows:     24,
		cols:     80,
		editor:   &lineEditor{},
		cancel:   cancel,
		sendDone: make(chan sendResult, 1),
	}
}

func TestInteractiveSendDoesNotBlockInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, clientConn := dialBlockable(t, ctx)
	clientConn.block.Store(true)

	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	im := newTestInteractiveMode(conn, cancelSession)
	im.editor.setText("first")

	start := time.Now()
	im.sendMessage(sessionCtx)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("sendMessage blocked for %v", elapsed)
	}
	if !im.sending {
		t.Fatal("sendMessage did not start a write")
	}

	// A second Enter while the write runs keeps the new text.
	im.editor.setText("next")
	im.sendMessage(sessionCtx)
	if got := string(im.editor.buf); got != "next" {
		t.Fatalf("editor text = %q, want %q", got, "next")
	}
	if im.status != "previous message is still sending" {
		t.Fatalf("status = %q", im.status)
	}

	// Ctrl+C is handled at once and stops the blocked write.
	im.handleInput(sessionCtx, []byte{0x03})
	if sessionCtx.Err() == nil {
		t.Fatal("Ctrl+C did not cancel the session")
	}
	select {
	case result := <-im.sendDone:
		if result.err == nil {
			t.Fatal("blocked write succeeded after cancellation")
		}
		if err := im.finishSend(result); err != nil {
			t.Fatalf("finishSend() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked write did not stop after cancellation")
	}
	if im.sending {
		t.Fatal("sending is still true after finishSend")
	}
	// The new text stays; the failed message does not replace it.
	if got := string(im.editor.buf); got != "next" {
		t.Fatalf("editor text after failed send = %q, want %q", got, "next")
	}
}

func TestInteractiveSendSuccessAndFailureRestoresText(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _ := dialBlockable(t, ctx)
	im := newTestInteractiveMode(conn, cancel)

	im.editor.setText("hello")
	im.sendMessage(ctx)
	if err := im.finishSend(<-im.sendDone); err != nil {
		t.Fatal(err)
	}
	if im.status != "sent 5 bytes" || len(im.messages) != 1 {
		t.Fatalf("status = %q, messages = %d", im.status, len(im.messages))
	}

	// A failed write restores its text when the editor is empty.
	if err := im.finishSend(sendResult{text: "lost?", err: errors.New("boom")}); err != nil {
		t.Fatal(err)
	}
	if got := string(im.editor.buf); got != "lost?" {
		t.Fatalf("editor text = %q, want restored text", got)
	}

	// A failed initial message ends the session; a cancelled one does not.
	if err := im.finishSend(sendResult{initial: true, err: errors.New("boom")}); err == nil {
		t.Fatal("failed initial message did not return an error")
	}
	if err := im.finishSend(sendResult{initial: true, err: context.Canceled}); err != nil {
		t.Fatalf("cancelled initial message returned %v", err)
	}
}

func TestInteractiveSendRefusedAfterLocalEOF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _ := dialBlockable(t, ctx)
	im := newTestInteractiveMode(conn, cancel)
	im.localEOF = true
	im.editor.setText("late")
	im.sendMessage(ctx)
	if im.sending {
		t.Fatal("sendMessage started a write after Ctrl+D")
	}
	if got := string(im.editor.buf); got != "late" {
		t.Fatalf("editor text = %q, want it kept", got)
	}
}
