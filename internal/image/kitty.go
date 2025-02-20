package image

import (
	"fmt"
	"image"
	"os"
)

const esc = "\033"

func writeKitty(img image.Image, termWidthPx, termHeightPx int) error {
	img = resizeForTerm(img, termWidthPx, termHeightPx)
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	data, err := encodeToBase64PNG(img)
	if err != nil {
		return err
	}

	next := min(4096, len(data))
	chunk := data[:next]
	fmt.Fprintf(os.Stdout, "%s_Gq=2,f=100,a=T,t=d,s=%d,v=%d,m=%d;%s%s\\",
		esc, width, height, boolToInt(next < len(data)), chunk, esc)

	pos := next
	for pos < len(data) {
		next = min(pos+4096, len(data))
		chunk = data[pos:next]
		pos = next

		fmt.Fprintf(os.Stdout, "%s_Gm=%d;%s%s\\",
			esc, boolToInt(next < len(data)), chunk, esc)
	}

	fmt.Fprintln(os.Stdout)
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
