//go:build windows

package core

import (
	"os"

	"golang.org/x/sys/windows"
)

// GetTerminalSize returns the terminal size, or an error if unavailable.
func GetTerminalSize() (TerminalSize, error) {
	var ts TerminalSize

	var info windows.ConsoleScreenBufferInfo
	handle := windows.Handle(int(os.Stdout.Fd()))
	err := windows.GetConsoleScreenBufferInfo(handle, &info)
	if err != nil {
		return ts, err
	}

	ts.Cols = int(info.Window.Right - info.Window.Left + 1)
	ts.Rows = int(info.Window.Bottom - info.Window.Top + 1)
	// Windows console doesn't provide pixel dimensions
	ts.WidthPx = 0
	ts.HeightPx = 0
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
