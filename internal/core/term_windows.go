//go:build windows

package core

import "golang.org/x/sys/windows"

func isTerminal(fd int) bool {
	var st uint32
	err := windows.GetConsoleMode(windows.Handle(fd), &st)
	return err == nil
}
