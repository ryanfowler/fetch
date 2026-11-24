//go:build !windows

package client

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// lockH3CacheFile takes an exclusive advisory lock on the file name in dir,
// and creates the file if necessary. On a local file system, the kernel
// releases the lock when the process exits, so a crash cannot leave a stale
// lock. (On NFS, the server releases it when the lock lease expires, and a
// mount without lock support makes every cache update fail.) The file is
// never removed: removing a lock file while another process opens it would
// let two processes hold locks on different files.
func lockH3CacheFile(dir, name string) (*h3CacheLock, error) {
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(dirFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	_ = unix.Close(dirFD)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(h3CacheLockWait)
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return &h3CacheLock{release: func() {
				_ = unix.Flock(fd, unix.LOCK_UN)
				_ = unix.Close(fd)
			}}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			_ = unix.Close(fd)
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			_ = unix.Close(fd)
			return nil, os.ErrDeadlineExceeded
		}
		time.Sleep(min(5*time.Millisecond, remaining))
	}
}
