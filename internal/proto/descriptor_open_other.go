//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !zos

package proto

import "os"

// openDescriptorSetFile keeps the same open-then-handle-stat invariant on
// platforms without the Unix nonblocking-open API used by the supported Unix
// targets.
func openDescriptorSetFile(path string) (*os.File, os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, errDescriptorSetNotRegular
	}
	return file, info, nil
}
