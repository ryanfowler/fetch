//go:build unix

package update

import (
	"archive/tar"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/klauspost/compress/gzip"
)

// unpackArtifact decodes the gzipped tar archive from the provided io.Reader
// into "dir", returning any error.
func unpackArtifact(dir string, r io.Reader) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	gr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		err = handleHeader(root, tr, header)
		if err != nil {
			return err
		}
	}
}

// handleHeader writes the provided file/directory as appropriate.
func handleHeader(root *os.Root, tr *tar.Reader, header *tar.Header) error {
	name := header.Name

	// Create parent directories if needed.
	if dir := path.Dir(name); dir != "." {
		if err := root.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	if header.Typeflag == tar.TypeDir {
		return root.Mkdir(name, os.FileMode(header.Mode))
	}
	if header.Typeflag != tar.TypeReg {
		return nil
	}

	f, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY, os.FileMode(header.Mode))
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, tr)
	return err
}

// selfReplace replaces the current executable, exePath, with a new executable,
// newExePath, returning any error encountered.
func selfReplace(exePath, newExePath string) error {
	// Fast path, attempt to rename from the temp directory.
	if os.Rename(newExePath, exePath) == nil {
		return nil
	}

	// Otherwise, copy the file into the same directory as the existing
	// binary and attempt the rename again.
	tempPath := createTempFilePath(filepath.Dir(exePath), ".__temp")
	defer os.Remove(tempPath)

	err := copyFile(tempPath, newExePath)
	if err != nil {
		return err
	}

	return os.Rename(tempPath, exePath)
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

// canReplaceFile returns true if this process can replace the file at the
// provided location.
func canReplaceFile(path string) bool {
	return unix.Access(path, unix.W_OK) == nil
}
