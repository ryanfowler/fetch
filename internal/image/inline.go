package image

import (
	"fmt"
	"image"
	"os"
)

// writeInline writes the provided image to the terminal using iTerm2's inline
// image protocol.
func writeInline(img image.Image, termWidthPx, termHeightPx int) error {
	img = resizeForTerm(img, termWidthPx, termHeightPx)
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	data, err := encodeToBase64PNG(img)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "\x1b]1337;File=inline=1;preserveAspectRatio=1;size=%d;width=%dpx;height=%dpx:%s\x07\n",
		len(data), width, height, data)
	return nil
}
