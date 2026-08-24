//go:build !windows

package pager

import (
	"errors"
	"syscall"
	"time"
)

func testProcessExited(pid int) bool {
	err := syscall.Kill(pid, 0)
	return errors.Is(err, syscall.ESRCH)
}

func killTestProcess(pid int) {
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

func waitForTestProcessExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if testProcessExited(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}
