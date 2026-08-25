package image

import (
	"fmt"
	"image"
	"io"
)

func writeKittyTo(img image.Image, termWidthPx, termHeightPx int, dst io.Writer) error {
	img = resizeForTerm(img, termWidthPx, termHeightPx)
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	data, err := encodeToBase64PNG(img)
	if err != nil {
		return err
	}

	// The image is written in chunks of up to 4096 bytes.
	next := min(4096, len(data))
	chunk := data[:next]
	if _, err := fmt.Fprintf(dst, "\x1b_Gq=2,f=100,a=T,t=d,s=%d,v=%d,m=%d;%s\x1b\\",
		width, height, boolToInt(next < len(data)), chunk); err != nil {
		return err
	}

	pos := next
	for pos < len(data) {
		next = min(pos+4096, len(data))
		chunk = data[pos:next]
		pos = next

		if _, err := fmt.Fprintf(dst, "\x1b_Gm=%d;%s\x1b\\",
			boolToInt(next < len(data)), chunk); err != nil {
			return err
		}
	}

	_, err = fmt.Fprintln(dst)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
