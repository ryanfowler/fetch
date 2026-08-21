//go:build windows

package pager

import "os/exec"

// Windows process-tree containment is best-effort here. The direct pager is
// always terminated; the pager parser does not invoke a shell, which limits
// the usual descendant-process risk.
func configureProcess(cmd *exec.Cmd) {}

func terminateProcessTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func pagerExitWasSIGPIPE(error) bool { return false }
