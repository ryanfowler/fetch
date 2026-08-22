//go:build !windows

package update

import (
	"os"
	"syscall"
)

// openUpdateMetadata opens only a regular directory entry. O_NOFOLLOW closes
// the symlink race between the advisory Lstat and the open, while O_NONBLOCK
// prevents a replaced FIFO from making an automatic check hang.
func openUpdateMetadata(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
