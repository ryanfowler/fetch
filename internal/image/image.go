package image

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	_ "image/jpeg"
	"image/png"
	"strings"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
)

// Render renders the provided raw image to stdout based on what protocol the
// current terminal emulator supports.
func Render(ctx context.Context, b []byte, nativeOnly bool) error {
	img, err := decodeImage(ctx, b, nativeOnly)
	if err != nil {
		return err
	}
	img = orientImage(b, img)

	bounds := img.Bounds()
	if bounds.Dx() == 0 || bounds.Dy() == 0 {
		// Exit early if the image has a zero width or height.
		return nil
	}

	size, err := getTerminalSize()
	if err != nil {
		return err
	}
	if size.widthPx == 0 || size.heightPx == 0 {
		// If we're unable to get the terminal dimensions in pixels,
		// render the image using blocks.
		return writeBlocks(img, size.cols, size.rows)
	}

	switch detectEmulator().Protocol() {
	case protoInline:
		return writeInline(img, size.widthPx, size.heightPx)
	case protoKitty:
		return writeKitty(img, size.widthPx, size.heightPx)
	default:
		return writeBlocks(img, size.cols, size.rows)
	}
}

func decodeImage(ctx context.Context, b []byte, nativeOnly bool) (image.Image, error) {
	img, err := decodeImageStd(b)
	if err == nil {
		return img, nil
	}
	if nativeOnly {
		return nil, err
	}

	// Unable to decode the image ourselves, attempt with the adaptors.
	var errAdaptor error
	img, errAdaptor = decodeWithAdaptors(ctx, b)
	if errAdaptor == nil {
		return img, nil
	}

	return nil, err
}

func decodeImageStd(b []byte) (image.Image, error) {
	const limit = 8192
	config, _, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	if config.Height > limit || config.Width > limit {
		return nil, fmt.Errorf("image dimensions are too large %dx%d", config.Width, config.Height)
	}

	img, _, err := image.Decode(bytes.NewReader(b))
	return img, err
}

// resizeForTerm returns a new image that has been resized to fit in less than
// 80% of the terminal height.
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

// resizeImage returns a new image that has been scaled to the provided width
// and height.
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

type terminalSize struct {
	cols     int
	rows     int
	widthPx  int
	heightPx int
}
