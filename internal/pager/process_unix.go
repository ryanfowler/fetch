//go:build !windows

package pager

import (
	"errors"
	"os/exec"
	"syscall"
)

func configureProcess(cmd *exec.Cmd, interactive bool) error {
	if interactive {
		// The pager must stay in the foreground process group to read commands
		// from the terminal. The parent still owns the pager's data pipe.
		return nil
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

func attachProcess(*exec.Cmd) error { return nil }

func releaseProcess(*exec.Cmd) {}

func terminateProcessTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil && pgid != syscall.Getpgrp() {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	_ = cmd.Process.Kill()
}

// requestProcessExit asks a pager that shares fetch's process group to exit.
// Such a pager owns the terminal, and SIGTERM lets it restore the terminal
// state; SIGKILL would leave the terminal without echo. It reports false
// when no signal was sent, for example for a pager in its own process group.
func requestProcessExit(cmd *exec.Cmd) bool {
	if cmd.Process == nil {
		return false
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil || pgid != syscall.Getpgrp() {
		return false
	}
	return cmd.Process.Signal(syscall.SIGTERM) == nil
}

func pagerExitWasSIGPIPE(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGPIPE
}
