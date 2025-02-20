//go:build windows

package image

func getTermSizeInPixels() (int, int, error) {
	return 0, 0, nil
}
