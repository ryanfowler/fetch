//go:build windows

package update

import (
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
)

// randomString returns a random string of lower-case letters of length n.
func randomString(n int) string {
	var sb strings.Builder
	sb.Grow(n)

	const letters = "abcdefghijklmnopqrstuvwxyz"
	for range n {
		sb.WriteByte(letters[rand.IntN(len(letters))])
	}
	return sb.String()
}

// createTempFilePath returns a generated path in dir. Callers create it with
// exclusive flags and treat a collision as a failure.
func createTempFilePath(dir, suffix string) string {
	return filepath.Join(dir, ".fetch."+randomString(16)+suffix)
}

func copyFile(dst, src string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	info, err := srcFile.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("source is not a non-empty regular file")
	}

	dstFile, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(dst)
		}
	}()

	n, err := io.CopyN(dstFile, srcFile, info.Size())
	if err != nil {
		_ = dstFile.Close()
		if errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	if n != info.Size() {
		_ = dstFile.Close()
		return io.ErrUnexpectedEOF
	}
	var extra [1]byte
	if n, err := srcFile.Read(extra[:]); n != 0 || err != io.EOF {
		_ = dstFile.Close()
		return errors.New("source changed while copying")
	}
	if err := dstFile.Sync(); err != nil {
		_ = dstFile.Close()
		return err
	}
	if err := dstFile.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}
