package fetch

import "testing"

func TestIsImageContentType(t *testing.T) {
	for _, contentType := range []string{"image/png", "IMAGE/JPEG; charset=binary"} {
		if !isImageContentType(contentType) {
			t.Errorf("isImageContentType(%q) = false", contentType)
		}
	}
	for _, contentType := range []string{"text/plain", "application/octet-stream", ""} {
		if isImageContentType(contentType) {
			t.Errorf("isImageContentType(%q) = true", contentType)
		}
	}
}
