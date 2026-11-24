package fileutil

import (
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// tempSuffix returns the random part of a temporary file name. Tests replace
// it to force name collisions.
var tempSuffix = func() string { return strconv.FormatUint(rand.Uint64(), 36) }

// CreateTemp creates a new file in dir with a name that starts with prefix,
// and opens it for reading and writing. Unlike os.CreateTemp, which uses
// mode 0600, it uses mode 0666 and the kernel removes the bits of the
// process umask. A file that CreateTemp makes and that a caller later
// installs therefore gets the same permissions as a file that a shell
// redirect makes. prefix must not contain a path separator.
//
// The open uses O_EXCL, so it never follows a symlink or opens an existing
// file at the chosen name. It tries another name instead.
func CreateTemp(dir, prefix string) (*os.File, error) {
	if strings.ContainsFunc(prefix, func(r rune) bool { return r < 0x80 && os.IsPathSeparator(uint8(r)) }) {
		return nil, &os.PathError{Op: "createtemp", Path: prefix, Err: errors.New("pattern contains path separator")}
	}
	for range 10000 {
		name := filepath.Join(dir, prefix+tempSuffix())
		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return f, err
	}
	return nil, &os.PathError{Op: "createtemp", Path: filepath.Join(dir, prefix+"*"), Err: os.ErrExist}
}
