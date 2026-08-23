//go:build !windows

package update

import (
	"os/exec"
	"syscall"
)

func configureProbeProcess(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

func attachProbeProcess(*exec.Cmd) error { return nil }

func terminateProbeProcess(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
	}
}

func releaseProbeProcess(*exec.Cmd) {}
