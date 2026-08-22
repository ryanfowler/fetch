//go:build !windows

package update

import (
	"os/exec"
	"syscall"
)

// ConfigureDetachedProcess gives the updater its own session and process
// group. It therefore does not receive terminal-generated signals sent to the
// initiating command's session.
func ConfigureDetachedProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
