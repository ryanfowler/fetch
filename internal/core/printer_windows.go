//go:build windows

package core

import (
	"os"

	"golang.org/x/sys/windows"
)

func init() {
	// Enable virtual terminal processing for both stderr and stdout.
	// https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences
	_ = enableVirtualTerminalProcessing(windows.Handle(os.Stderr.Fd()))
	_ = enableVirtualTerminalProcessing(windows.Handle(os.Stdout.Fd()))
}

func enableVirtualTerminalProcessing(handle windows.Handle) error {
	var mode uint32
	err := windows.GetConsoleMode(handle, &mode)
	if err != nil {
		return err
	}

	mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	return windows.SetConsoleMode(handle, mode)
}
