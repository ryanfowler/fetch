//go:build windows

package image

import (
	"os"

	"golang.org/x/sys/windows"
)

func getTerminalSize() (terminalSize, error) {
	var ts terminalSize

	var info windows.ConsoleScreenBufferInfo
	handle := windows.Handle(int(os.Stdout.Fd()))
	err := windows.GetConsoleScreenBufferInfo(handle, &info)
	if err != nil {
		return ts, err
	}

	ts.cols = int(info.Window.Right - info.Window.Left + 1)
	ts.rows = int(info.Window.Bottom - info.Window.Top + 1)
	return ts, nil
}
