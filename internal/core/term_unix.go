//go:build unix

package core

import "golang.org/x/sys/unix"

func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, ioctlTermiosReq)
	return err == nil
}
