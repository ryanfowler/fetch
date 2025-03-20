//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package core

import "golang.org/x/sys/unix"

const ioctlTermiosReq = unix.TIOCGETA
