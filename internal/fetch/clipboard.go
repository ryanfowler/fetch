package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/ryanfowler/fetch/internal/body"
	"github.com/ryanfowler/fetch/internal/core"
)

// limitedBuffer captures up to max bytes into buf, then silently discards
// overflow. It always reports the full write so the response stream can keep
// delivering bytes after the clipboard cap is reached.
type limitedBuffer struct {
	buf      bytes.Buffer
	max      int64
	written  int64
	overflow bool
}

func (lb *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if lb.overflow {
		return n, nil
	}
	remaining := lb.max - lb.written
	if int64(n) > remaining {
		lb.overflow = true
		if remaining > 0 {
			lb.buf.Write(p[:remaining])
		}
		lb.written = lb.max
		return n, nil
	}
	lb.buf.Write(p)
	lb.written += int64(n)
	return n, nil
}

// clipboardCopier handles capturing the raw response body and copying it
// to the system clipboard. Use newClipboardCopier to set up body wrapping,
// then call finish after the response has been consumed.
type clipboardCopier struct {
	cmd    *clipboardCmd
	buf    *limitedBuffer
	silent bool
}

const clipboardCommandTimeout = 5 * time.Second

// newClipboardCopier sets up clipboard copying for the response. If copying
// is not enabled or not possible, it returns nil and resp is left unchanged.
// When non-nil is returned, resp.Body has been wrapped with a TeeReader
// that captures raw bytes into an internal buffer.
func newClipboardCopier(r *Request, resp *http.Response) *clipboardCopier {
	if !r.Copy {
		return nil
	}

	cmd := findClipboard()
	if cmd == nil {
		p := r.PrinterHandle.Stderr()
		var msg string
		switch runtime.GOOS {
		case "darwin":
			msg = "no clipboard command found; install pbcopy"
		case "windows":
			msg = "no clipboard command found; install clip.exe"
		default:
			msg = "no clipboard command found; install xclip, xsel, or wl-copy"
		}
		core.WriteWarningMsgIf(p, msg, r.Verbosity == core.VSilent)
		return nil
	}

	buf := &limitedBuffer{max: maxBodyBytes}
	if stream, ok := resp.Body.(*body.Stream); ok {
		stream.AddTee(buf)
	} else {
		stream := body.NewStream(resp.Body)
		stream.AddTee(buf)
		resp.Body = stream
	}
	return &clipboardCopier{cmd: cmd, buf: buf, silent: r.Verbosity == core.VSilent}
}

// setBytes replaces the captured payload after a presentation transform such
// as article extraction. It preserves the existing clipboard size limit.
func (cc *clipboardCopier) setBytes(data []byte) {
	if cc == nil {
		return
	}
	cc.buf = &limitedBuffer{max: maxBodyBytes}
	_, _ = cc.buf.Write(data)
}

// finish copies the captured bytes to the system clipboard. It writes a
// warning to stderr on failure but never returns an error.
func (cc *clipboardCopier) finish(ctx context.Context, p *core.Printer) {
	if cc == nil {
		return
	}
	if cc.buf.overflow {
		core.WriteWarningMsgIf(p, "--copy: response body too large to copy to clipboard", cc.silent)
		return
	}
	if err := copyToClipboard(ctx, cc.cmd, cc.buf.buf.Bytes()); err != nil {
		core.WriteWarningMsgIf(p, "unable to copy to clipboard: "+err.Error(), cc.silent)
	}
}

type clipboardCmd struct {
	path string
	args []string
}

func findClipboard() *clipboardCmd {
	switch runtime.GOOS {
	case "darwin":
		if path, err := exec.LookPath("pbcopy"); err == nil {
			return &clipboardCmd{path: path}
		}
	case "windows":
		if path, err := exec.LookPath("clip.exe"); err == nil {
			return &clipboardCmd{path: path}
		}
		if path, err := exec.LookPath("clip"); err == nil {
			return &clipboardCmd{path: path}
		}
	default:
		if path, err := exec.LookPath("wl-copy"); err == nil {
			return &clipboardCmd{path: path}
		}
		if path, err := exec.LookPath("xclip"); err == nil {
			return &clipboardCmd{path: path, args: []string{"-selection", "clipboard"}}
		}
		if path, err := exec.LookPath("xsel"); err == nil {
			return &clipboardCmd{path: path, args: []string{"--clipboard", "--input"}}
		}
	}
	return nil
}

func copyToClipboard(ctx context.Context, clip *clipboardCmd, data []byte) error {
	return copyToClipboardWithTimeout(ctx, clip, data, clipboardCommandTimeout)
}

func copyToClipboardWithTimeout(ctx context.Context, clip *clipboardCmd, data []byte, timeout time.Duration) error {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(commandCtx, clip.path, clip.args...)
	cmd.Stdin = bytes.NewReader(data)
	if err := cmd.Run(); err != nil {
		if ctxErr := commandCtx.Err(); ctxErr != nil {
			if errors.Is(ctxErr, context.DeadlineExceeded) && ctx.Err() == nil {
				return fmt.Errorf("clipboard command timed out after %s", timeout)
			}
			return fmt.Errorf("clipboard command canceled: %w", ctxErr)
		}
		return fmt.Errorf("clipboard command failed: %w", err)
	}
	return nil
}
