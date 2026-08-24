//go:build windows

package update

import (
	"archive/zip"
	"encoding/json"
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
	archive, err := os.CreateTemp(dir, ".fetch-update-archive-*")
	if err != nil {
		return err
	}
	archivePath := archive.Name()
	defer func() {
		_ = archive.Close()
		_ = os.Remove(archivePath)
	}()

	size, err := io.Copy(archive, io.LimitReader(r, core.MaxUpdaterArtifactBytes+1))
	if err != nil {
		return err
	}
	if size > core.MaxUpdaterArtifactBytes {
		return core.LimitError{Subsystem: "update archive", Limit: core.MaxUpdaterArtifactBytes}
	}
	if err := archive.Sync(); err != nil {
		return err
	}
	return unpackArtifactFile(dir, archive, size)
}

// unpackArtifactFile extracts the verified disk-backed archive directly with
// zip.NewReader. The archive has already been hashed and closed by the
// downloader, so its size is the compressed archive limit without materializing
// another copy in memory.
func unpackArtifactFile(dir string, archive *os.File, size int64) error {
	if err := validateExtractionRoot(dir); err != nil {
		return err
	}
	if archive == nil {
		return errors.New("archive file is nil")
	}
	if size < 0 || size > core.MaxUpdaterArtifactBytes {
		return core.LimitError{Subsystem: "update archive", Limit: core.MaxUpdaterArtifactBytes}
	}
	info, err := archive.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != size {
		return errors.New("verified archive file changed")
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	zr, err := zip.NewReader(archive, size)
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

// The following Windows self-replace functionality uses safe staged replacement
// and cleanup techniques.

const (
	relocatedSuffix           = ".__relocated.exe"
	selfDeleteSuffix          = ".__selfdelete.exe"
	tempSuffix                = ".__temp.exe"
	replacementJournalSuffix  = ".__update-journal"
	maxReplacementJournalSize = 1024
)

func init() {
	if data := os.Getenv("FETCH_INTERNAL_UPDATE_DELETE_HELPER"); data != "" {
		runHelperDeletion(data)
	}

	// Look for the environment variable that indicates this application
	// should reconcile an update and self-delete.
	data := os.Getenv("FETCH_INTERNAL_UPDATE_SELF_DELETE")
	if data == "" {
		recoverInterruptedSelfReplacement()
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
	parentHandleUint, err := strconv.ParseUint(handleStr, 10, 64)
	if err != nil {
		os.Exit(1)
	}
	parentHandle := windows.Handle(uintptr(parentHandleUint))

	waitRes, err := windows.WaitForSingleObject(parentHandle, windows.INFINITE)
	_ = windows.CloseHandle(parentHandle)
	if err != nil || waitRes != windows.WAIT_OBJECT_0 {
		os.Exit(1)
	}

	if err := reconcileReplacementJournal(origPath, ""); err != nil {
		os.Exit(1)
	}
	targetPath := strings.TrimSuffix(origPath, replacementJournalSuffix)
	if targetPath == origPath || scheduleFileDeletionAfterExit(targetPath, exePath) != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func runHelperDeletion(data string) {
	handleStr, path, ok := strings.Cut(data, "_")
	if !ok {
		os.Exit(1)
	}
	handleUint, err := strconv.ParseUint(handleStr, 10, 64)
	if err != nil {
		os.Exit(1)
	}
	handle := windows.Handle(uintptr(handleUint))
	waitRes, err := windows.WaitForSingleObject(handle, windows.INFINITE)
	_ = windows.CloseHandle(handle)
	if err != nil || waitRes != windows.WAIT_OBJECT_0 {
		os.Exit(1)
	}
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		os.Exit(1)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = windows.DeleteFile(pathUTF16)
		if err == nil || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			os.Exit(0)
		}
		if (!errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED)) || time.Now().After(deadline) {
			os.Exit(1)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// selfReplace stages beside the target, moves the running target aside, and
// installs the complete staged file. Windows cannot rename an executable that
// is still running, so the old file is scheduled for cleanup after exit.
func selfReplace(exePath, newExePath string) error {
	journalPath := exePath + replacementJournalSuffix
	if err := reconcileReplacementJournal(journalPath, ""); err != nil {
		return fmt.Errorf("recover interrupted replacement: %w", err)
	}
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
	journal := replacementJournal{
		Staged:    filepath.Base(tempExePath),
		Relocated: filepath.Base(oldExePath),
		OwnerPID:  uint32(os.Getpid()),
	}
	if err := writeReplacementJournal(journalPath, journal); err != nil {
		return err
	}
	if err := scheduleReplacementRecoveryOnShutdown(exePath, journalPath); err != nil {
		_ = os.Remove(journalPath)
		return err
	}
	if err := os.Rename(exePath, oldExePath); err != nil {
		_ = os.Remove(journalPath)
		return err
	}
	if err := os.Rename(tempExePath, exePath); err != nil {
		if rollbackErr := os.Rename(oldExePath, exePath); rollbackErr != nil {
			return errors.Join(err, rollbackErr)
		}
		_ = os.Remove(journalPath)
		return err
	}

	// The recovery child removes the journal and relocated executable after
	// this process exits. It also repairs a crash between the two renames.
	return nil
}

type replacementJournal struct {
	Staged    string `json:"staged"`
	Relocated string `json:"relocated"`
	OwnerPID  uint32 `json:"owner_pid"`
}

func writeReplacementJournal(path string, journal replacementJournal) error {
	if !validReplacementTempName(journal.Staged, tempSuffix) ||
		!validReplacementTempName(journal.Relocated, relocatedSuffix) || journal.OwnerPID == 0 {
		return errors.New("invalid replacement journal")
	}
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	tempPath := createTempFilePath(filepath.Dir(path), ".__journal.tmp")
	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(tempPath)
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// WRITE_THROUGH makes the journal rename durable before the executable
	// renames can begin.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func readReplacementJournal(path string) (replacementJournal, error) {
	var journal replacementJournal
	info, err := os.Lstat(path)
	if err != nil {
		return journal, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxReplacementJournalSize {
		return journal, errors.New("replacement journal is not a small regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return journal, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, maxReplacementJournalSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return journal, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return journal, errors.New("replacement journal contains trailing data")
	}
	if !validReplacementTempName(journal.Staged, tempSuffix) ||
		!validReplacementTempName(journal.Relocated, relocatedSuffix) || journal.OwnerPID == 0 {
		return journal, errors.New("replacement journal contains invalid data")
	}
	return journal, nil
}

func replacementOwnerRunning(pid uint32) (bool, error) {
	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(process)
	result, err := windows.WaitForSingleObject(process, 0)
	if err != nil {
		return false, err
	}
	switch result {
	case uint32(windows.WAIT_TIMEOUT):
		return true, nil
	case windows.WAIT_OBJECT_0:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected owner process wait result: %d", result)
	}
}

func validReplacementTempName(name, suffix string) bool {
	if filepath.Base(name) != name || !strings.HasPrefix(name, ".fetch.") || !strings.HasSuffix(name, suffix) {
		return false
	}
	randomPart := strings.TrimSuffix(strings.TrimPrefix(name, ".fetch."), suffix)
	if len(randomPart) != 16 {
		return false
	}
	for _, c := range randomPart {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// reconcileReplacementJournal completes or rolls back an interrupted pair of
// Windows renames. If currentExePath is set, the journal must describe that
// executable or its relocated predecessor.
func reconcileReplacementJournal(journalPath, currentExePath string) error {
	targetPath := strings.TrimSuffix(journalPath, replacementJournalSuffix)
	if targetPath == journalPath || filepath.Base(targetPath) == "" {
		return errors.New("invalid replacement journal path")
	}
	if err := validateReplacementDirectory(targetPath); err != nil {
		return err
	}
	targetExists, targetErr := regularReplacementFile(targetPath)
	if targetErr != nil {
		return targetErr
	}
	journal, err := readReplacementJournal(journalPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		// The journal is synced before either rename. If the original target
		// still exists, a truncated journal only records an uncommitted update.
		if targetExists {
			return os.Remove(journalPath)
		}
		return err
	}
	ownerRunning, err := replacementOwnerRunning(journal.OwnerPID)
	if err != nil {
		return err
	}
	if ownerRunning {
		return nil
	}
	dir := filepath.Dir(journalPath)
	stagedPath := filepath.Join(dir, journal.Staged)
	relocatedPath := filepath.Join(dir, journal.Relocated)
	if currentExePath != "" && !samePath(currentExePath, targetPath) && !samePath(currentExePath, relocatedPath) {
		return errors.New("replacement journal does not match the current executable")
	}

	if !targetExists {
		stagedExists, stagedErr := regularReplacementFile(stagedPath)
		if stagedErr != nil {
			return stagedErr
		}
		recoveryPath := stagedPath
		if !stagedExists {
			relocatedExists, relocatedErr := regularReplacementFile(relocatedPath)
			if relocatedErr != nil {
				return relocatedErr
			}
			if !relocatedExists {
				return errors.New("replacement journal has no recoverable executable")
			}
			recoveryPath = relocatedPath
		}
		if err := renameRegularReplacementFile(recoveryPath, targetPath); err != nil {
			return err
		}
	}

	var cleanupErr error
	for _, path := range []string{stagedPath, relocatedPath} {
		if samePath(path, currentExePath) {
			if _, err := os.Lstat(path); err == nil {
				cleanupErr = errors.Join(cleanupErr, errors.New("running relocated executable still needs cleanup"))
			} else if !os.IsNotExist(err) {
				cleanupErr = errors.Join(cleanupErr, err)
			}
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if cleanupErr != nil {
		return cleanupErr
	}
	return os.Remove(journalPath)
}

func regularReplacementFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() == 0 {
		return false, errors.New("replacement recovery file is not a non-empty regular file")
	}
	return true, nil
}

// renameRegularReplacementFile verifies that the path still names the opened
// regular file before and after the rename. This prevents a reparse-point swap
// from becoming the executable destination.
func renameRegularReplacementFile(source, target string) error {
	name, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(handle), source)
	if f == nil {
		_ = windows.CloseHandle(handle)
		return errors.New("unable to open replacement recovery source")
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Size() == 0 ||
		pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return errors.New("replacement recovery source changed")
	}
	if err := os.Rename(source, target); err != nil {
		return err
	}
	targetInfo, err := os.Lstat(target)
	if err != nil {
		return err
	}
	if targetInfo.Mode()&os.ModeSymlink != 0 || !targetInfo.Mode().IsRegular() {
		_ = os.Remove(target)
		return errors.New("replacement recovery installed a non-regular file")
	}
	if !os.SameFile(openedInfo, targetInfo) {
		if err := os.Remove(target); err != nil {
			return errors.Join(errors.New("replacement recovery source changed during rename"), err)
		}
		if err := restoreOpenedReplacementFile(f, openedInfo.Size(), target); err != nil {
			return errors.Join(errors.New("replacement recovery source changed during rename"), err)
		}
	}
	return nil
}

func restoreOpenedReplacementFile(source *os.File, size int64, target string) error {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	tempPath := createTempFilePath(filepath.Dir(target), tempSuffix)
	temp, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		_ = temp.Close()
		if !keep {
			_ = os.Remove(tempPath)
		}
	}()
	if n, err := io.CopyN(temp, source, size); err != nil || n != size {
		if err != nil {
			return err
		}
		return io.ErrUnexpectedEOF
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	keep = true
	return nil
}

func samePath(a, b string) bool {
	return b != "" && strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func recoverInterruptedSelfReplacement() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return
	}
	journalPath := exePath + replacementJournalSuffix
	if _, err := os.Lstat(journalPath); err == nil {
		_ = reconcileReplacementJournal(journalPath, exePath)
		return
	} else if !os.IsNotExist(err) {
		return
	}
	if !strings.HasSuffix(strings.ToLower(exePath), strings.ToLower(relocatedSuffix)) {
		return
	}
	journals, err := filepath.Glob(filepath.Join(filepath.Dir(exePath), "*"+replacementJournalSuffix))
	if err != nil {
		return
	}
	for i, journalPath := range journals {
		if i == 64 {
			return
		}
		journal, err := readReplacementJournal(journalPath)
		if err != nil {
			continue
		}
		relocatedPath := filepath.Join(filepath.Dir(journalPath), journal.Relocated)
		if !samePath(relocatedPath, exePath) {
			continue
		}
		if reconcileReplacementJournal(journalPath, exePath) == nil {
			return
		}
		_ = scheduleReplacementRecoveryOnShutdown(exePath, journalPath)
		return
	}
}

// scheduleReplacementRecoveryOnShutdown starts a child that reconciles the
// journal after this process exits.
func scheduleReplacementRecoveryOnShutdown(exePath, journalPath string) (err error) {
	success := false
	tempExePath := createTempFilePath(filepath.Dir(exePath), selfDeleteSuffix)
	defer func() {
		if success {
			return
		}
		var cleanupErr error
		if removeErr := os.Remove(tempExePath); removeErr != nil && !os.IsNotExist(removeErr) {
			cleanupErr = errors.Join(cleanupErr, removeErr)
		}
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("clean up replacement files: %w", cleanupErr))
		}
	}()

	if err := copyFile(tempExePath, exePath); err != nil {
		return err
	}

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
	envVar := fmt.Sprintf("FETCH_INTERNAL_UPDATE_SELF_DELETE=%d_%s", dupHandle, journalPath)
	cmd.Env = append(os.Environ(), envVar)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:                 true,
		AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(dupHandle)},
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()

	success = true
	return nil
}

func scheduleFileDeletionAfterExit(cleanerExePath, deletePath string) error {
	currentProcess := windows.CurrentProcess()
	var processHandle windows.Handle
	if err := windows.DuplicateHandle(
		currentProcess,
		currentProcess,
		currentProcess,
		&processHandle,
		0,
		true,
		windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		return err
	}
	defer windows.CloseHandle(processHandle)

	cmd := exec.Command(cleanerExePath)
	cmd.Env = append(os.Environ(), fmt.Sprintf("FETCH_INTERNAL_UPDATE_DELETE_HELPER=%d_%s", processHandle, deletePath))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:                 true,
		AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(processHandle)},
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
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
