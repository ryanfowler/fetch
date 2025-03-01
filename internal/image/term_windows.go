//go:build windows

package image

// getTermSizeInPixels always returns a zero width & height on windows.
func getTermSizeInPixels() (int, int, error) {
	return 0, 0, nil
}
