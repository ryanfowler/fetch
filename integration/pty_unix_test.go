//go:build (darwin || linux) && cgo

package integration_test

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	fetchintegration "github.com/ryanfowler/fetch/integration"
)

func TestImageRenderingPTY(t *testing.T) {
	fetchPath := testFetchBinary(t)
	imageBytes := testPTYImageBytes(t)

	server := startServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		w.Write(imageBytes)
	})
	defer server.Close()

	master, slave := fetchintegration.OpenPTY(t, 24, 80)
	defer master.Close()
	defer slave.Close()

	cmd := exec.Command(fetchPath, server.URL, "--format", "on", "--no-pager")
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Env = overlayEnv(os.Environ(), []string{
		"TERM=xterm-256color",
		"COLORTERM=",
		"TERM_PROGRAM=",
		"GHOSTTY_BIN_DIR=",
		"ITERM_SESSION_ID=",
		"KITTY_PID=",
		"KONSOLE_VERSION=",
		"VSCODE_INJECTION=",
		"WEZTERM_EXECUTABLE=",
		"WT_SESSION=",
		"ZELLIJ=",
	})
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start fetch under PTY: %v", err)
	}
	slave.Close()
	capture := startPTYCapture(master)
	defer capture.close()
	defer func() {
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			_ = cmd.Process.Kill()
			_, _ = waitProcess(cmd, time.Second)
		}
	}()

	if err, ok := waitProcess(cmd, 5*time.Second); !ok {
		t.Fatalf("fetch did not exit after image response; PTY output:\n%s", capture.string())
	} else if err != nil {
		t.Fatalf("fetch exited with error: %v; PTY output:\n%s", err, capture.string())
	}

	output := capture.string()
	if !strings.Contains(output, "\x1b[48;5;") || !strings.Contains(output, "\x1b[38;5;") {
		t.Fatalf("PTY output did not contain ANSI block colors; output:\n%q", output)
	}
	if !strings.Contains(output, "▄") {
		t.Fatalf("PTY output did not contain block-rendered image glyphs; output:\n%q", output)
	}
	if strings.Contains(output, "\x89PNG") {
		t.Fatalf("PTY output contained raw PNG bytes instead of rendered image; output:\n%q", output)
	}
}

func TestImageRenderingInlinePTY(t *testing.T) {
	fetchPath := testFetchBinary(t)
	output := runImageRenderPTY(t, fetchPath, imagePTYEnv(
		"TERM=xterm-256color",
		"TERM_PROGRAM=iTerm.app",
		"ITERM_SESSION_ID=fetch-test",
	))

	if !strings.Contains(output, "\x1b]1337;File=inline=1;preserveAspectRatio=1;") {
		t.Fatalf("PTY output did not contain iTerm2 inline image protocol; output:\n%q", output)
	}
	if strings.Contains(output, "\x89PNG") {
		t.Fatalf("PTY output contained raw PNG bytes instead of rendered image; output:\n%q", output)
	}
}

func TestImageRenderingKittyPTY(t *testing.T) {
	fetchPath := testFetchBinary(t)
	output := runImageRenderPTY(t, fetchPath, imagePTYEnv(
		"TERM=xterm-kitty",
		"KITTY_PID=123",
	))

	if !strings.Contains(output, "\x1b_Gq=2,f=100,a=T,t=d,") || !strings.Contains(output, "\x1b\\") {
		t.Fatalf("PTY output did not contain Kitty graphics protocol; output:\n%q", output)
	}
	if strings.Contains(output, "\x89PNG") {
		t.Fatalf("PTY output contained raw PNG bytes instead of rendered image; output:\n%q", output)
	}
}

func TestWebSocketInteractivePTY(t *testing.T) {
	fetchPath := testFetchBinary(t)
	received := make(chan string, 1)
	server := startServer(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		typ, data, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		received <- string(data)
		conn.Write(r.Context(), typ, []byte("echo: "+string(data)))
		conn.Close(websocket.StatusNormalClosure, "done")
	})
	defer server.Close()

	master, slave := fetchintegration.OpenPTY(t, 24, 80)
	defer master.Close()
	defer slave.Close()

	wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
	cmd := exec.Command(fetchPath, wsURL, "--ws-interactive", "on", "--format", "off", "--no-pager")
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Env = overlayEnv(os.Environ(), []string{"TERM=xterm-256color"})
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start fetch under PTY: %v", err)
	}
	slave.Close()
	capture := startPTYCapture(master)
	defer capture.close()
	defer func() {
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			_ = cmd.Process.Kill()
			_, _ = waitProcess(cmd, time.Second)
		}
	}()

	capture.waitFor(t, "connected", 5*time.Second)
	if _, err := master.Write([]byte("hello pty\r")); err != nil {
		t.Fatalf("failed to write interactive input: %v", err)
	}

	select {
	case got := <-received:
		if got != "hello pty" {
			t.Fatalf("websocket server received %q, want %q", got, "hello pty")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for interactive WebSocket send; PTY output:\n%s", capture.string())
	}

	capture.waitFor(t, "echo: hello pty", 5*time.Second)
	if err, ok := waitProcess(cmd, 5*time.Second); !ok {
		t.Fatalf("fetch did not exit after WebSocket close; PTY output:\n%s", capture.string())
	} else if err != nil {
		t.Fatalf("fetch exited with error: %v; PTY output:\n%s", err, capture.string())
	}
}

func testPTYImageBytes(t *testing.T) []byte {
	t.Helper()

	var imageBytes bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	img.Set(1, 0, color.RGBA{G: 255, A: 255})
	img.Set(0, 1, color.RGBA{B: 255, A: 255})
	img.Set(1, 1, color.RGBA{R: 255, G: 255, B: 255, A: 255})
	if err := png.Encode(&imageBytes, img); err != nil {
		t.Fatalf("failed to encode test png: %v", err)
	}
	return imageBytes.Bytes()
}

func imagePTYEnv(overrides ...string) []string {
	env := []string{
		"TERM=xterm-256color",
		"COLORTERM=",
		"TERM_PROGRAM=",
		"GHOSTTY_BIN_DIR=",
		"ITERM_SESSION_ID=",
		"KITTY_PID=",
		"KONSOLE_VERSION=",
		"VSCODE_INJECTION=",
		"WEZTERM_EXECUTABLE=",
		"WT_SESSION=",
		"ZELLIJ=",
	}
	return append(env, overrides...)
}

func runImageRenderPTY(t *testing.T, fetchPath string, env []string) string {
	t.Helper()

	imageBytes := testPTYImageBytes(t)
	server := startServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		w.Write(imageBytes)
	})
	defer server.Close()

	master, slave := fetchintegration.OpenPTYWithPixels(t, 24, 80, 800, 480)
	defer master.Close()
	defer slave.Close()

	cmd := exec.Command(fetchPath, server.URL, "--format", "on", "--no-pager")
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Env = overlayEnv(os.Environ(), env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start fetch under PTY: %v", err)
	}
	slave.Close()
	capture := startPTYCapture(master)
	defer capture.close()
	defer func() {
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			_ = cmd.Process.Kill()
			_, _ = waitProcess(cmd, time.Second)
		}
	}()

	if err, ok := waitProcess(cmd, 5*time.Second); !ok {
		t.Fatalf("fetch did not exit after image response; PTY output:\n%s", capture.string())
	} else if err != nil {
		t.Fatalf("fetch exited with error: %v; PTY output:\n%s", err, capture.string())
	}
	return capture.string()
}

type ptyCapture struct {
	file      *os.File
	done      chan struct{}
	mu        sync.Mutex
	buf       bytes.Buffer
	responded bool
}

func startPTYCapture(file *os.File) *ptyCapture {
	c := &ptyCapture{
		file: file,
		done: make(chan struct{}),
	}
	go c.readLoop()
	return c
}

func (c *ptyCapture) readLoop() {
	defer close(c.done)
	buf := make([]byte, 1024)
	for {
		n, err := c.file.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			c.mu.Lock()
			c.buf.Write(chunk)
			needsCursorResponse := !c.responded && bytes.Contains(c.buf.Bytes(), []byte("\x1b[6n"))
			if needsCursorResponse {
				c.responded = true
			}
			c.mu.Unlock()
			if needsCursorResponse {
				_, _ = c.file.Write([]byte("\x1b[1;1R"))
			}
		}
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
	}
}

func (c *ptyCapture) waitFor(t *testing.T, want string, timeout time.Duration) {
	t.Helper()

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		if strings.Contains(c.string(), want) {
			return
		}
		select {
		case <-c.done:
			if strings.Contains(c.string(), want) {
				return
			}
			t.Fatalf("PTY closed before output contained %q; output:\n%s", want, c.string())
		case <-deadline.C:
			t.Fatalf("timed out waiting for PTY output %q; output:\n%s", want, c.string())
		case <-tick.C:
		}
	}
}

func (c *ptyCapture) string() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func (c *ptyCapture) close() {
	_ = c.file.Close()
	<-c.done
}

func waitProcess(cmd *exec.Cmd, timeout time.Duration) (error, bool) {
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	select {
	case err := <-done:
		return err, true
	case <-time.After(timeout):
		return nil, false
	}
}
