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
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// unpackArtifact decodes the zip archive from the provided io.Reader into
// "dir", returning any error encountered.
func unpackArtifact(dir string, r io.Reader) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	// Read the archive into memory, as we need an io.ReaderAt.
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	ra := bytes.NewReader(data)

	zr, err := zip.NewReader(ra, int64(len(data)))
	if err != nil {
		return err
	}

	for _, f := range zr.File {
		err = handleZipFile(root, f)
		if err != nil {
			return err
		}
	}

	return nil
}

// handleZipFile writes the provided directory/file to dir.
func handleZipFile(root *os.Root, f *zip.File) error {
	name := f.Name

	// Create parent directories if needed.
	if dir := path.Dir(name); dir != "." {
		if err := root.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	if f.FileInfo().IsDir() {
		return root.Mkdir(name, f.Mode())
	}

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, rc)
	return err
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

	// Ensure the appication has the self-delete suffix.
	exePath, err := os.Executable()
	if err != nil || !strings.HasSuffix(exePath, selfDeleteSuffix) {
		return
	}

	// Parse out the parent handle and original application path.
	handleStr, origPath, ok := strings.Cut(data, "_")
	if !ok {
		os.Exit(1)
	}
	handleUint, err := strconv.ParseUint(handleStr, 10, 64)
	if err != nil {
		os.Exit(1)
	}
	parentHandle := windows.Handle(uintptr(handleUint))

	// Wait indefinitely for the parent process to exit.
	waitRes, err := windows.WaitForSingleObject(parentHandle, windows.INFINITE)
	if err != nil || waitRes != windows.WAIT_OBJECT_0 {
		os.Exit(1)
	}

	// Delete the original file.
	originalFileUTF16, err := windows.UTF16PtrFromString(origPath)
	if err != nil || windows.DeleteFile(originalFileUTF16) != nil {
		os.Exit(1)
	}

	// To force Windows to notice the DELETE_ON_CLOSE flag on our inherited
	// handle, spawn a short-lived process (using cmd.exe) that will
	// inherit the handle.
	cmd := exec.Command("cmd.exe", "/c", "exit")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()

	os.Exit(0)
}

// selfReplace replaces the current executable, exePath, with a new executable,
// newExePath, returning any error encountered.
func selfReplace(exePath, newExePath string) error {
	dir := filepath.Dir(exePath)
	oldExePath := createTempFilePath(dir, relocatedSuffix)
	err := os.Rename(exePath, oldExePath)
	if err != nil {
		return err
	}

	err = scheduleSelfDeletionOnShutdown(oldExePath)
	if err != nil {
		return err
	}

	tempExePath := createTempFilePath(dir, tempSuffix)
	err = copyFile(tempExePath, newExePath)
	if err != nil {
		return err
	}

	return os.Rename(tempExePath, exePath)
}

// scheduleSelfDeletionOnShutdown arranges for the given executable to be
// deleted when the process shuts down.
func scheduleSelfDeletionOnShutdown(exePath string) error {
	exeDir := filepath.Dir(exePath)
	tempDir := os.TempDir()
	relocatedExePath := createTempFilePath(tempDir, relocatedSuffix)
	if os.Rename(exePath, relocatedExePath) == nil {
		exeDir = tempDir
		exePath = relocatedExePath
	}

	tempExePath := createTempFilePath(exeDir, selfDeleteSuffix)
	if err := copyFile(tempExePath, exePath); err != nil {
		return err
	}

	tempExePathUTF16, err := windows.UTF16PtrFromString(tempExePath)
	if err != nil {
		return err
	}

	// Prepare security attributes so that the handle is inheritable.
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle:      1,
		SecurityDescriptor: nil,
	}

	// Open the temporary exe file with DELETE_ON_CLOSE behavior.
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

	// Duplicate the current process handle so that the child can wait on it.
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

	// Launch the temporary executable.
	// Pass two arguments: the duplicate handle as a string and the original exe path.
	cmd := exec.Command(tempExePath)
	envVar := fmt.Sprintf("FETCH_INTERNAL_UPDATE_SELF_DELETE=%d_%s", dupHandle, exePath)
	cmd.Env = append(os.Environ(), envVar)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return err
	}

	// Some implementations sleep here to ensure the child inherits the handle.
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

// canReplaceFile always returns true on windows.
func canReplaceFile(_ string) bool {
	return true
}
