package fetch

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"runtime"

	"github.com/ryanfowler/fetch/internal/core"
)

// clipboardCopier handles capturing the raw response body and copying it
// to the system clipboard. Use newClipboardCopier to set up body wrapping,
// then call finish after the response has been consumed.
type clipboardCopier struct {
	cmd *clipboardCmd
	buf *bytes.Buffer
}

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
		core.WriteWarningMsg(p, msg)
		return nil
	}

	contentType := getContentType(resp.Header)
	if contentType == TypeSSE || contentType == TypeNDJSON || contentType == TypeGRPC {
		p := r.PrinterHandle.Stderr()
		core.WriteWarningMsg(p, "--copy is not supported for streaming responses")
		return nil
	}

	buf := &bytes.Buffer{}
	resp.Body = readCloserTee{
		Reader: io.TeeReader(io.LimitReader(resp.Body, maxBodyBytes), buf),
		Closer: resp.Body,
	}
	return &clipboardCopier{cmd: cmd, buf: buf}
}

// finish copies the captured bytes to the system clipboard. It writes a
// warning to stderr on failure but never returns an error.
func (cc *clipboardCopier) finish(p *core.Printer) {
	if cc == nil || cc.buf.Len() == 0 {
		return
	}
	if err := copyToClipboard(cc.cmd, cc.buf.Bytes()); err != nil {
		core.WriteWarningMsg(p, "unable to copy to clipboard: "+err.Error())
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

func copyToClipboard(clip *clipboardCmd, data []byte) error {
	cmd := exec.Command(clip.path, clip.args...)
	cmd.Stdin = bytes.NewReader(data)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clipboard command failed: %w", err)
	}
	return nil
}

// readCloserTee wraps a Reader and a separate Closer, allowing the
// underlying reader to be replaced (e.g. with a TeeReader) while
// preserving the original Closer.
type readCloserTee struct {
	io.Reader
	io.Closer
}
