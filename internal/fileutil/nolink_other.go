//go:build !unix && !windows

package fileutil

import "errors"

// linkUnsupported reports false: this platform has no fallback, so a link
// error is returned as it is.
func linkUnsupported(error) bool { return false }

func writeNewFileWithoutLink(string, string) error {
	return errors.New("no fallback for a failed link on this platform")
}
