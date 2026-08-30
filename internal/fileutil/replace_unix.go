//go:build !windows

package fileutil

import (
	"errors"
	"os"
)

var (
	ErrSymlinkTarget = errors.New("refusing to replace a symlink target")
	errTargetChanged = errors.New("output target changed during commit")
)

// AtomicReplaceFile atomically replaces targetPath with tempPath.
// tempPath and targetPath must be on the same filesystem.
func AtomicReplaceFile(tempPath, targetPath string) error {
	return os.Rename(tempPath, targetPath)
}

// AtomicReplaceFileNoSymlink atomically replaces targetPath, but refuses a
// symlink that was present when the commit was attempted. The check is paired
// with rename: rename never follows the final target symlink, so a race cannot
// redirect the staged bytes outside targetPath.
func AtomicReplaceFileNoSymlink(tempPath, targetPath string) error {
	return atomicReplaceFileNoSymlink(tempPath, targetPath, false)
}

// AtomicReplaceFileNoSymlinkPreserveMode atomically replaces targetPath while
// inheriting the permission bits of an existing target. A target that does not
// exist at commit time retains tempPath's permissions.
func AtomicReplaceFileNoSymlinkPreserveMode(tempPath, targetPath string) error {
	return atomicReplaceFileNoSymlink(tempPath, targetPath, true)
}

func atomicReplaceFileNoSymlink(tempPath, targetPath string, preserveMode bool) error {
	// Serialize fileutil commits so concurrent fetches cannot invalidate each
	// other's identity check. The final rename never follows a symlink.
	noSymlinkCommitMu.Lock()
	defer noSymlinkCommitMu.Unlock()

	info, err := os.Lstat(targetPath)
	if os.IsNotExist(err) {
		// A no-replace install closes the missing-target race. If another
		// regular file appeared, retry below as a normal clobber; if a symlink
		// appeared, AtomicWriteNewFile fails without touching it.
		if err := AtomicWriteNewFile(tempPath, targetPath); err == nil {
			return nil
		} else if committedError(err) {
			return err
		} else if !os.IsExist(err) {
			return err
		}
		info, err = os.Lstat(targetPath)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrSymlinkTarget
	}
	if !info.Mode().IsRegular() {
		return errors.New("output target is not a regular file")
	}
	latest, err := os.Lstat(targetPath)
	if err != nil {
		return err
	}
	if !os.SameFile(info, latest) {
		return errTargetChanged
	}
	if preserveMode {
		if err := os.Chmod(tempPath, latest.Mode().Perm()); err != nil {
			return err
		}
	}
	// os.Rename replaces the directory entry and never follows the final
	// target symlink. The identity check prevents a detected replacement from
	// being mistaken for the file we validated.
	return os.Rename(tempPath, targetPath)
}

// AtomicWriteNewFile atomically installs tempPath at targetPath only if targetPath
// does not already exist. tempPath and targetPath must be on the same filesystem.
func AtomicWriteNewFile(tempPath, targetPath string) error {
	if err := os.Link(tempPath, targetPath); err != nil {
		return err
	}
	// Report cleanup failures with committed state so callers retain
	// responsibility for the temporary path without treating the install as a
	// failed write.
	if err := os.Remove(tempPath); err != nil {
		return &CommittedError{Err: err}
	}
	return nil
}
