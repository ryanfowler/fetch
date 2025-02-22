//go:build unix

package update

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
)

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

func selfReplace(exePath, newExePath string) error {
	stat, err := os.Stat(exePath)
	if err != nil {
		return err
	}

	exeDir := filepath.Dir(exePath)
	tempPath, err := createTemp(exeDir, stat.Mode())
	if err != nil {
		return err
	}
	defer os.Remove(tempPath)

	if err = copyFile(tempPath, newExePath); err != nil {
		return err
	}

	return os.Rename(tempPath, exePath)

}

func createTemp(dir string, mode os.FileMode) (string, error) {
	name := ".fetch.temp." + randomString(12)
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return "", err
	}
	defer f.Close()

	return f.Name(), nil
}

func copyFile(dst, src string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}
