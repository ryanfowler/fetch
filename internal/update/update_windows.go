//go:build windows

package update

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
)

func unpackArtifact(dir string, r io.Reader) error {
	// Read the archive into memory.
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
		err = handleZipFile(dir, f)
		if err != nil {
			return err
		}
	}

	return nil
}

func handleZipFile(dir string, f *zip.File) error {
	target := filepath.Join(dir, f.Name)

	if f.FileInfo().IsDir() {
		err := os.MkdirAll(target, f.Mode())
		if err != nil {
			return err
		}
		return err
	}

	err := os.MkdirAll(filepath.Dir(target), 0755)
	if err != nil {
		return err
	}

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, rc)
	return err
}
