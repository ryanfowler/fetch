//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// configureDetachedProcess gives the updater its own session and process
// group. It therefore does not receive terminal-generated signals sent to the
// initiating command's session.
func configureDetachedProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
