package ws

import (
	"bytes"
	"os"
	"strconv"
	"sync"

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

func extractCursorRow(buf []byte) (row int, remaining []byte, ok bool) {
	for i := 0; i < len(buf); i++ {
		if buf[i] != 0x1b || i+1 >= len(buf) || buf[i+1] != '[' {
			continue
		}

		j := i + 2
		for j < len(buf) && buf[j] >= '0' && buf[j] <= '9' {
			j++
		}
		if j == i+2 || j >= len(buf) || buf[j] != ';' {
			continue
		}
		j++

		colStart := j
		for j < len(buf) && buf[j] >= '0' && buf[j] <= '9' {
			j++
		}
		if j == colStart || j >= len(buf) || buf[j] != 'R' {
			continue
		}

		row = parseCursorRow(buf[i : j+1])
		remaining = append(append([]byte{}, buf[:i]...), buf[j+1:]...)
		return row, remaining, true
	}

	return 0, append([]byte{}, buf...), false
}
