//go:build !windows

package proto

import (
	"os/exec"
	"syscall"
)

func configureProtocProcess(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

func attachProtocProcess(*exec.Cmd) error { return nil }

func releaseProtocProcess(*exec.Cmd) {}

func terminateProtocProcess(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
}
