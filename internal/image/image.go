package image

import (
	"bytes"
	"encoding/base64"
	"image"
	_ "image/jpeg"
	"image/png"
	"strings"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
)

func Render(b []byte) error {
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return err
	}
	img = orient(b, img)

	termWidthPx, termHeightPx, err := getTermSizeInPixels()
	if err != nil {
		return err
	}
	if termWidthPx == 0 || termHeightPx == 0 {
		// If we're unable to get the terminal dimensions in pixels,
		// render the image using blocks.
		return writeBlocks(img)
	}

	switch detectEmulator().Protocol() {
	case protoInline:
		return writeInline(img, termWidthPx, termHeightPx)
	case protoKitty:
		return writeKitty(img, termWidthPx, termHeightPx)
	default:
		return writeBlocks(img)
	}
}

func resizeForTerm(img image.Image, termWidthPx, termHeightPx int) image.Image {
	if termWidthPx == 0 || termHeightPx == 0 {
		return img
	}

	// Use only 4/5ths of the terminal height.
	termHeightPx = termHeightPx * 4 / 5

	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	if width <= termWidthPx && height <= termHeightPx {
		return img
	}

	aspectRatio := float64(width) / float64(height)
	termAspectRatio := float64(termWidthPx) / float64(termHeightPx)
	if aspectRatio > termAspectRatio {
		h := int(float64(termWidthPx) / aspectRatio)
		return resizeImage(img, termWidthPx, h)
	}
	w := int(float64(termHeightPx) * aspectRatio)
	return resizeImage(img, w, termHeightPx)
}

func resizeImage(img image.Image, width, height int) image.Image {
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.ApproxBiLinear.Scale(dst, dst.Rect, img, img.Bounds(), draw.Over, nil)
	return dst
}

func encodeToBase64PNG(img image.Image) (string, error) {
	img = convertToRGBA(img)

	var sb strings.Builder
	wc := base64.NewEncoder(base64.StdEncoding, &sb)

	err := png.Encode(wc, img)
	if err != nil {
		return "", err
	}

	wc.Close()
	return sb.String(), nil
}

func convertToRGBA(img image.Image) *image.RGBA {
	switch img := img.(type) {
	case *image.RGBA:
		return img
	default:
		bounds := img.Bounds()
		out := image.NewRGBA(bounds)
		draw.Draw(out, bounds, img, bounds.Min, draw.Src)
		return out
	}
}
