package image

import (
	"fmt"
	"image"
	"io"
)

func writeInlineTo(img image.Image, termWidthPx, termHeightPx int, dst io.Writer) error {
	img = resizeForTerm(img, termWidthPx, termHeightPx)
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	data, err := encodeToBase64PNG(img)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(dst, "\x1b]1337;File=inline=1;preserveAspectRatio=1;size=%d;width=%dpx;height=%dpx:%s\x07\n",
		len(data), width, height, data)
	return err
}
