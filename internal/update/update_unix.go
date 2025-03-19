//go:build unix

package update

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// unpackArtifact decodes the gzipped tar archive from the provided io.Reader
// into "dir", returning any error.
func unpackArtifact(dir string, r io.Reader) error {
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
		err = handleHeader(dir, tr, header)
		if err != nil {
			return err
		}
	}
}

// handleHeader writes the provided file/directory as appropriate.
func handleHeader(dir string, tr *tar.Reader, header *tar.Header) error {
	target := filepath.Join(dir, header.Name)
	if header.Typeflag == tar.TypeDir {
		return os.MkdirAll(target, os.FileMode(header.Mode))
	}
	if header.Typeflag != tar.TypeReg {
		return nil
	}

	err := os.MkdirAll(filepath.Dir(target), 0755)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, os.FileMode(header.Mode))
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
