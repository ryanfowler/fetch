//go:build !windows

package fetch

import (
	"os/exec"
	"syscall"
)

func configureClipboardProcess(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

func attachClipboardProcess(*exec.Cmd) error { return nil }

func releaseClipboardProcess(*exec.Cmd) {}

func terminateClipboardProcessTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
}
