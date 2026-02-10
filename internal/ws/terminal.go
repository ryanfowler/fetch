package ws

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ryanfowler/fetch/internal/core"

	"golang.org/x/term"
)

// terminal manages raw mode and terminal dimensions.
type terminal struct {
	fd    int
	saved *term.State

	mu   sync.Mutex
	rows int
	cols int
}

func newTerminal() *terminal {
	return &terminal{fd: int(os.Stdin.Fd())}
}

func (t *terminal) enterRaw() error {
	state, err := term.MakeRaw(t.fd)
	if err != nil {
		return err
	}
	t.saved = state
	t.refreshSize()
	return nil
}

func (t *terminal) restore() {
	if t.saved != nil {
		term.Restore(t.fd, t.saved)
	}
}

func (t *terminal) refreshSize() {
	ts, err := core.GetTerminalSize()
	if err != nil {
		return
	}
	t.mu.Lock()
	t.rows = ts.Rows
	t.cols = ts.Cols
	t.mu.Unlock()
}

func (t *terminal) size() (rows, cols int) {
	t.mu.Lock()
	rows = t.rows
	cols = t.cols
	t.mu.Unlock()
	return
}

// cursorRow queries the terminal for the current cursor row using the
// Device Status Report (DSR) escape sequence. Must be called in raw mode
// and before any goroutine is reading stdin. Returns 1 on failure.
func (t *terminal) cursorRow() int {
	// Request cursor position: response is ESC [ row ; col R
	fmt.Fprint(os.Stdout, "\x1b[6n")

	type readResult struct {
		resp []byte
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		var resp []byte
		var buf [32]byte
		for {
			n, err := os.Stdin.Read(buf[:])
			if n > 0 {
				resp = append(resp, buf[:n]...)
				if bytes.ContainsRune(resp, 'R') {
					ch <- readResult{resp: resp}
					return
				}
			}
			if err != nil {
				ch <- readResult{err: err}
				return
			}
		}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			return 1
		}
		return parseCursorRow(res.resp)
	case <-time.After(time.Second):
		return 1
	}
}

func parseCursorRow(resp []byte) int {
	start := bytes.IndexByte(resp, '[')
	semi := bytes.IndexByte(resp, ';')
	if start < 0 || semi < 0 || start >= semi {
		return 1
	}
	row, err := strconv.Atoi(string(resp[start+1 : semi]))
	if err != nil {
		return 1
	}
	return row
}
