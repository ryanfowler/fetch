//go:build !windows

package image

import (
	"os/exec"
	"sync"
	"syscall"
)

func configureProcess(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

var imagePGIDs sync.Map // map[*exec.Cmd]int

func attachProcess(cmd *exec.Cmd) error {
	imagePGIDs.Store(cmd, cmd.Process.Pid)
	return nil
}

func releaseProcess(cmd *exec.Cmd) {
	imagePGIDs.Delete(cmd)
}

func terminateProcessTree(cmd *exec.Cmd) {
	if value, ok := imagePGIDs.Load(cmd); ok {
		_ = syscall.Kill(-value.(int), syscall.SIGKILL)
		return
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
