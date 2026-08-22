//go:build windows

package update

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/fileutil"
)

// unpackArtifact decodes a bounded zip archive into dir. Only the expected
// executable at the archive root is accepted.
func unpackArtifact(dir string, r io.Reader) error {
	if err := validateExtractionRoot(dir); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(r, core.MaxUpdaterArtifactBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > core.MaxUpdaterArtifactBytes {
		return core.LimitError{Subsystem: "update archive", Limit: core.MaxUpdaterArtifactBytes}
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	if len(zr.File) > core.MaxUpdaterArchiveEntries {
		return core.LimitError{Subsystem: "update archive entries", Limit: core.MaxUpdaterArchiveEntries}
	}

	var total int64
	found := false
	for _, f := range zr.File {
		name, err := archiveEntryName(f.Name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() || f.Mode()&os.ModeSymlink != 0 || !f.Mode().IsRegular() {
			return fmt.Errorf("archive entry %q is not a regular executable", f.Name)
		}
		if found || name != getFetchFilename() {
			return fmt.Errorf("archive contains duplicate executable entry %q", f.Name)
		}
		if f.UncompressedSize64 == 0 || f.UncompressedSize64 > uint64(core.MaxUpdaterUnpackedDataBytes) {
			return core.LimitError{Subsystem: "update archive entry", Limit: core.MaxUpdaterUnpackedDataBytes}
		}
		if total > core.MaxUpdaterUnpackedDataBytes-int64(f.UncompressedSize64) {
			return core.LimitError{Subsystem: "unpacked update archive", Limit: core.MaxUpdaterUnpackedDataBytes}
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := openExtractedExecutable(dir)
		if err != nil {
			_ = rc.Close()
			return err
		}
		copyErr := copyArchiveEntry(out, rc, int64(f.UncompressedSize64), &total)
		if closeErr := rc.Close(); copyErr == nil {
			copyErr = closeErr
		}
		if syncErr := out.Sync(); copyErr == nil {
			copyErr = syncErr
		}
		if closeErr := out.Close(); copyErr == nil {
			copyErr = closeErr
		}
		if copyErr != nil {
			_ = os.Remove(filepath.Join(dir, getFetchFilename()))
			return copyErr
		}
		if err := os.Chmod(filepath.Join(dir, getFetchFilename()), 0755); err != nil {
			_ = os.Remove(filepath.Join(dir, getFetchFilename()))
			return err
		}
		found = true
	}
	if !found {
		return errors.New("archive does not contain the fetch executable")
	}
	return nil
}

// The following Windows self-replace functionality uses similar techniques to
// the 'self-replace' Rust crate: https://github.com/mitsuhiko/self-replace

const (
	relocatedSuffix  = ".__relocated.exe"
	selfDeleteSuffix = ".__selfdelete.exe"
	tempSuffix       = ".__temp.exe"
)

func init() {
	// Look for the environment variable that indicates this application
	// should self-delete.
	data := os.Getenv("FETCH_INTERNAL_UPDATE_SELF_DELETE")
	if data == "" {
		return
	}

	exePath, err := os.Executable()
	if err != nil || !strings.HasSuffix(exePath, selfDeleteSuffix) {
		return
	}

	handleStr, origPath, ok := strings.Cut(data, "_")
	if !ok {
		os.Exit(1)
	}
	handleUint, err := strconv.ParseUint(handleStr, 10, 64)
	if err != nil {
		os.Exit(1)
	}
	parentHandle := windows.Handle(uintptr(handleUint))

	waitRes, err := windows.WaitForSingleObject(parentHandle, windows.INFINITE)
	if err != nil || waitRes != windows.WAIT_OBJECT_0 {
		os.Exit(1)
	}

	originalFileUTF16, err := windows.UTF16PtrFromString(origPath)
	if err != nil || windows.DeleteFile(originalFileUTF16) != nil {
		os.Exit(1)
	}

	cmd := exec.Command("cmd.exe", "/c", "exit")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
	os.Exit(0)
}

// selfReplace stages beside the target, moves the running target aside, and
// installs the complete staged file. Windows cannot rename an executable that
// is still running, so the old file is scheduled for cleanup after exit.
func selfReplace(exePath, newExePath string) error {
	if err := validateReplacementDirectory(exePath); err != nil {
		return err
	}
	info, err := os.Lstat(exePath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fileutil.ErrSymlinkTarget
	}
	if !info.Mode().IsRegular() {
		return errors.New("executable destination is not a regular file")
	}
	candidateInfo, err := os.Lstat(newExePath)
	if err != nil {
		return err
	}
	if candidateInfo.Mode()&os.ModeSymlink != 0 || !candidateInfo.Mode().IsRegular() {
		return errors.New("staged executable is not a regular file")
	}

	dir := filepath.Dir(exePath)
	tempExePath := createTempFilePath(dir, tempSuffix)
	if err := copyFile(tempExePath, newExePath); err != nil {
		return err
	}
	defer os.Remove(tempExePath)
	if err := os.Chmod(tempExePath, 0755); err != nil {
		return err
	}

	oldExePath := createTempFilePath(dir, relocatedSuffix)
	if err := os.Rename(exePath, oldExePath); err != nil {
		return err
	}
	if err := os.Rename(tempExePath, exePath); err != nil {
		if rollbackErr := os.Rename(oldExePath, exePath); rollbackErr != nil {
			return errors.Join(err, rollbackErr)
		}
		return err
	}
	if err := scheduleSelfDeletionOnShutdown(oldExePath); err != nil {
		// The new executable is already installed. Do not claim that the
		// original was preserved; leave the old path for conservative cleanup.
		return &fileutil.CommittedError{Err: err}
	}
	return nil
}

// scheduleSelfDeletionOnShutdown arranges for the given executable to be
// deleted when the process shuts down.
func scheduleSelfDeletionOnShutdown(exePath string) (err error) {
	exeDir := filepath.Dir(exePath)
	tempDir := os.TempDir()
	relocatedExePath := createTempFilePath(tempDir, relocatedSuffix)
	if os.Rename(exePath, relocatedExePath) == nil {
		exeDir = tempDir
		exePath = relocatedExePath
	}

	success := false
	tempExePath := createTempFilePath(exeDir, selfDeleteSuffix)
	defer func() {
		if success {
			return
		}
		var cleanupErr error
		if removeErr := os.Remove(tempExePath); removeErr != nil && !os.IsNotExist(removeErr) {
			cleanupErr = errors.Join(cleanupErr, removeErr)
		}
		// Keep the relocated old executable. Windows may still need it for
		// recovery, and deleting the only old copy after a post-commit failure
		// would make rollback impossible.
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("clean up replacement files: %w", cleanupErr))
		}
	}()

	if err := copyFile(tempExePath, exePath); err != nil {
		return err
	}

	tempExePathUTF16, err := windows.UTF16PtrFromString(tempExePath)
	if err != nil {
		return err
	}

	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle:      1,
		SecurityDescriptor: nil,
	}

	handle, err := windows.CreateFile(tempExePathUTF16,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		&sa,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_DELETE_ON_CLOSE,
		0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	currentProcess := windows.CurrentProcess()
	var dupHandle windows.Handle
	err = windows.DuplicateHandle(
		currentProcess,
		currentProcess,
		currentProcess,
		&dupHandle,
		0,
		true,
		windows.DUPLICATE_SAME_ACCESS)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(dupHandle)

	cmd := exec.Command(tempExePath)
	envVar := fmt.Sprintf("FETCH_INTERNAL_UPDATE_SELF_DELETE=%d_%s", dupHandle, exePath)
	cmd.Env = append(os.Environ(), envVar)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return err
	}

	success = true
	time.Sleep(100 * time.Millisecond)
	return nil
}

const allBytes = ^uint32(0)

func tryLockFile(f *os.File) (bool, error) {
	var ol windows.Overlapped
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, allBytes, allBytes, &ol)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return false, err
}

func unlockFile(f *os.File) error {
	var ol windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, allBytes, allBytes, &ol)
}

func validateReplacementDirectory(target string) error {
	info, err := os.Lstat(filepath.Dir(target))
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("replacement directory is not a real directory")
	}
	return nil
}

func canReplaceFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
