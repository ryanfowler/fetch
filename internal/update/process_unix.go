//go:build !windows

package update

import (
	"os/exec"
	"syscall"
)

func configureValidationProcess(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

func attachValidationProcess(*exec.Cmd) error { return nil }

func terminateValidationProcess(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
	}
}

func releaseValidationProcess(*exec.Cmd) {}
