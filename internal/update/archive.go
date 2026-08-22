package update

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"strings"
	"unicode"

	"github.com/ryanfowler/fetch/internal/core"
)

// archiveEntryName is deliberately narrow. Release archives are not general
// file bundles: they contain one executable at their root. Keeping this
// contract narrow removes the need to make archive-controlled directories safe.
func archiveEntryName(name string) (string, error) {
	if name == "" {
		return "", errors.New("archive contains an empty entry name")
	}
	if strings.IndexByte(name, 0) >= 0 {
		return "", errors.New("archive entry contains NUL")
	}
	if strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("archive entry %q uses a backslash", name)
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "//") {
		return "", fmt.Errorf("archive entry %q is an absolute path", name)
	}
	if len(name) >= 2 && ((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')) && name[1] == ':' {
		return "", fmt.Errorf("archive entry %q has a drive-letter path", name)
	}

	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == "." && i == 0 {
			continue
		}
		if part == ".." {
			return "", fmt.Errorf("archive entry %q contains path traversal", name)
		}
		if part == "" || (part == "." && i != 0) {
			return "", fmt.Errorf("archive entry %q is not a normalized path", name)
		}
		if strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return "", fmt.Errorf("archive entry %q has an unsafe trailing character", name)
		}
		for _, r := range part {
			if unicode.IsControl(r) {
				return "", fmt.Errorf("archive entry %q contains a control character", name)
			}
		}
	}

	expected := getFetchFilename()
	switch name {
	case expected:
		return expected, nil
	case "./" + expected:
		return expected, nil
	default:
		return "", fmt.Errorf("archive contains unexpected entry %q", name)
	}
}

const maxTarStreamBytes = core.MaxUpdaterUnpackedDataBytes + int64(core.MaxUpdaterArchiveEntries)*1024

// tarAuditReader counts physical tar entries before archive/tar hides PAX and
// GNU metadata entries. It also caps decompressed tar bytes, which prevents a
// metadata-only archive from bypassing the logical entry/data limits.
type tarAuditReader struct {
	source    io.Reader
	header    [512]byte
	headerLen int
	remaining int64
	entries   int
	rawBytes  int64
	ended     bool
	failure   error
}

func (r *tarAuditReader) Read(p []byte) (int, error) {
	if r.failure != nil {
		return 0, r.failure
	}
	n, err := r.source.Read(p)
	if n > 0 {
		r.rawBytes += int64(n)
		if r.rawBytes > maxTarStreamBytes {
			r.failure = core.LimitError{Subsystem: "unpacked update archive", Limit: core.MaxUpdaterUnpackedDataBytes}
			return n, r.failure
		}
		for i := 0; i < n; {
			if r.ended {
				break
			}
			if r.remaining > 0 {
				consume := int64(n - i)
				if consume > r.remaining {
					consume = r.remaining
				}
				i += int(consume)
				r.remaining -= consume
				continue
			}
			consume := len(r.header) - r.headerLen
			if consume > n-i {
				consume = n - i
			}
			copy(r.header[r.headerLen:], p[i:i+consume])
			r.headerLen += consume
			i += consume
			if r.headerLen == len(r.header) {
				r.headerLen = 0
				if tarBlockIsZero(r.header[:]) {
					r.ended = true
					continue
				}
				r.entries++
				if r.entries > core.MaxUpdaterArchiveEntries {
					r.failure = core.LimitError{Subsystem: "update archive entries", Limit: core.MaxUpdaterArchiveEntries}
					return n, r.failure
				}
				size := parseTarOctal(r.header[124:136])
				if size < 0 || size > math.MaxInt64-511 {
					r.failure = errors.New("archive contains an invalid entry size")
					return n, r.failure
				}
				r.remaining = (size + 511) &^ 511
			}
		}
	}
	if r.failure != nil {
		return n, r.failure
	}
	return n, err
}

func tarBlockIsZero(block []byte) bool {
	for _, b := range block {
		if b != 0 {
			return false
		}
	}
	return true
}

func parseTarOctal(field []byte) int64 {
	field = bytes.Trim(field, " \x00")
	if len(field) == 0 {
		return 0
	}
	var value int64
	for _, b := range field {
		if b < '0' || b > '7' || value > (math.MaxInt64-int64(b-'0'))/8 {
			return -1
		}
		value = value*8 + int64(b-'0')
	}
	return value
}

func tarHeaderHasSparseMetadata(records map[string]string) bool {
	for key := range records {
		if strings.HasPrefix(key, "GNU.sparse.") {
			return true
		}
	}
	return false
}

func validateExtractionRoot(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("extraction directory is not a real directory")
	}
	return nil
}

// copyArchiveEntry copies exactly the declared entry size and verifies that
// the archive reader has no more data for that entry. It never allocates based
// on an archive-controlled size.
func copyArchiveEntry(dst *os.File, src io.Reader, size int64, total *int64) error {
	if size < 0 || size > core.MaxUpdaterUnpackedDataBytes {
		return core.LimitError{Subsystem: "update archive entry", Limit: core.MaxUpdaterUnpackedDataBytes}
	}
	if *total > core.MaxUpdaterUnpackedDataBytes-size {
		return core.LimitError{Subsystem: "unpacked update archive", Limit: core.MaxUpdaterUnpackedDataBytes}
	}

	n, err := io.CopyN(dst, src, size)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	if n != size {
		return io.ErrUnexpectedEOF
	}
	var extra [1]byte
	nread, err := src.Read(extra[:])
	if nread != 0 {
		return errors.New("archive entry contains more data than declared")
	}
	if err != io.EOF {
		if err == nil {
			return errors.New("archive entry size could not be verified")
		}
		return err
	}
	*total += size
	return nil
}

func openExtractedExecutable(dir string) (*os.File, error) {
	path := path.Join(dir, getFetchFilename())
	// O_EXCL is important even though the extraction directory is private: it
	// prevents a caller accidentally reusing an extraction directory from
	// turning an archive entry into a truncating write.
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
}
