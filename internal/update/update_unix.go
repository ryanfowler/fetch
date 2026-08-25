//go:build unix

package update

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/klauspost/compress/gzip"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/fileutil"
)

// unpackArtifact decodes the gzipped tar archive into dir. Release archives
// contain exactly one root-level executable; no archive-controlled path is
// ever opened or created.
func unpackArtifact(dir string, r io.Reader) error {
	if err := validateExtractionRoot(dir); err != nil {
		return err
	}

	gr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(&tarAuditReader{source: gr})
	var total int64
	var entries int
	found := false
	for {
		header, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			if err := gr.Close(); err != nil {
				return err
			}
			if !found {
				return errors.New("archive does not contain the fetch executable")
			}
			return nil
		}
		if nextErr != nil {
			return nextErr
		}
		entries++
		if entries > core.MaxUpdaterArchiveEntries {
			return core.LimitError{Subsystem: "update archive entries", Limit: core.MaxUpdaterArchiveEntries}
		}
		name, err := archiveEntryName(header.Name)
		if err != nil {
			return err
		}
		if header.Typeflag != tar.TypeReg || header.Linkname != "" || tarHeaderHasSparseMetadata(header.PAXRecords) {
			return fmt.Errorf("archive entry %q is not a regular executable", header.Name)
		}
		if found || name != getFetchFilename() {
			return fmt.Errorf("archive contains duplicate executable entry %q", header.Name)
		}
		if header.Size < 0 || header.Size == 0 {
			return errors.New("archive executable is empty")
		}

		out, err := openExtractedExecutable(dir)
		if err != nil {
			return err
		}
		copyErr := copyArchiveEntry(out, tr, header.Size, &total)
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
}

// unpackArtifactFile extracts the verified archive file. Unix archives are
// streamed by the tar reader, but keep the file-based entry point shared with
// Windows so the updater always extracts the already-verified disk-backed
// archive.
func unpackArtifactFile(dir string, archive *os.File, size int64) error {
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
	return unpackArtifact(dir, archive)
}

// selfReplace stages the new executable beside the destination and performs
// one checked rename. The final rename is atomic on Unix and never follows a
// destination symlink.
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
	staged, err := os.CreateTemp(dir, ".fetch-update-*")
	if err != nil {
		return err
	}
	stagedPath := staged.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(stagedPath)
		}
	}()

	if err := copyInto(staged, newExePath); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Chmod(0755); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Sync(); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if err := fileutil.AtomicReplaceFileNoSymlink(stagedPath, exePath); err != nil {
		return err
	}
	keep = true // rename consumed the staged path
	if err := fileutil.SyncDir(dir); err != nil {
		return &fileutil.CommittedError{Err: err}
	}
	return nil
}

func copyInto(dst *os.File, srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("staged executable is not a non-empty regular file")
	}
	n, err := io.CopyN(dst, src, info.Size())
	if err != nil {
		if errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	if n != info.Size() {
		return io.ErrUnexpectedEOF
	}
	var extra [1]byte
	if n, err := src.Read(extra[:]); n != 0 || err != io.EOF {
		return errors.New("staged executable changed while copying")
	}
	return nil
}

func tryLockFile(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	return false, err
}

func unlockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}

// validateReplacementDirectory prevents a less-privileged process from
// swapping the staged source path while it is being committed.
func validateReplacementDirectory(target string) error {
	info, err := os.Lstat(filepath.Dir(target))
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("replacement directory is not a real directory")
	}
	if info.Mode().Perm()&022 != 0 {
		dir := filepath.Dir(target)
		return fmt.Errorf("replacement directory %q is writable by group or others (mode %04o); remove group/other write permission by running `chmod go-w` on this directory (use `sudo` if needed), or install fetch in a private directory such as `~/.local/bin`", dir, info.Mode().Perm())
	}
	return nil
}

// canReplaceFile returns true if this process can replace the file at the
// provided location. On Unix, the containing directory controls rename.
func canReplaceFile(path string) bool {
	dir := filepath.Dir(path)

	f, err := os.CreateTemp(dir, ".fetch-update-*")
	if err != nil {
		return false
	}

	name := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return false
	}

	return os.Remove(name) == nil
}
