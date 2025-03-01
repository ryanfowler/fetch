//go:build unix

package image

import (
	"os"

	"golang.org/x/sys/unix"
)

// getTermSizeInPixels returns the size of the terminal in pixels on unix.
func getTermSizeInPixels() (int, int, error) {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0, err
	}
	return int(ws.Xpixel), int(ws.Ypixel), nil
}
