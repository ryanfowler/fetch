//go:build unix

package core

import (
	"os"

	"golang.org/x/sys/unix"
)

// GetTerminalSize returns the terminal size, or an error if unavailable.
func GetTerminalSize() (TerminalSize, error) {
	var ts TerminalSize
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return ts, err
	}

	ts.Cols = int(ws.Col)
	ts.Rows = int(ws.Row)
	ts.WidthPx = int(ws.Xpixel)
	ts.HeightPx = int(ws.Ypixel)
	return ts, nil
}

// GetTerminalCols returns the number of columns in the terminal, or 0 if unavailable.
func GetTerminalCols() int {
	ts, err := GetTerminalSize()
	if err != nil {
		return 0
	}
	return ts.Cols
}
