//go:build unix

package image

import (
	"os"

	"golang.org/x/sys/unix"
)

func getTerminalSize() (terminalSize, error) {
	var ts terminalSize
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return ts, err
	}

	ts.cols = int(ws.Col)
	ts.rows = int(ws.Row)
	ts.widthPx = int(ws.Xpixel)
	ts.heightPx = int(ws.Ypixel)
	return ts, nil
}
