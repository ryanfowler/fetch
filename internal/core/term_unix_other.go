//go:build aix || linux || solaris || zos

package core

import "golang.org/x/sys/unix"

const ioctlTermiosReq = unix.TCGETS
