package image

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	"image/png"
	"io"
	"math"
	"os"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
)

// Render renders the provided raw image to stdout using the legacy boolean
// API. A true value restricts decoding to built-in decoders. New callers
// should use RenderWithMode so auto mode cannot accidentally run a process.
func Render(ctx context.Context, b []byte, nativeOnly bool) error {
	mode := core.ImageExternal
	if nativeOnly {
		mode = core.ImageNative
	}
	return RenderWithMode(ctx, b, mode)
}

// RenderWithMode renders an image using the requested image policy. Unknown
// and auto modes are deliberately built-in-only. External processes are an
// explicit opt-in because image responses are untrusted input and adapters
// have a much larger attack surface than the Go decoders.
func RenderWithMode(ctx context.Context, b []byte, mode core.ImageSetting) error {
	return RenderWithModeTo(ctx, b, mode, os.Stdout)
}

// RenderWithModeTo decodes an image and writes its terminal presentation to
// dst. Keeping the destination explicit lets Markdown presentation buffer
// image protocols together with the surrounding document.
func RenderWithModeTo(ctx context.Context, b []byte, mode core.ImageSetting, dst io.Writer) error {
	if mode == core.ImageOff {
		return errors.New("image rendering is disabled")
	}
	if dst == nil {
		return errors.New("image rendering destination is nil")
	}
	img, err := decodeImage(ctx, b, mode)
	if err != nil {
		return err
	}
	img = orientImage(b, img)

	bounds := img.Bounds()
	if bounds.Dx() == 0 || bounds.Dy() == 0 {
		// Exit early if the image has a zero width or height.
		return nil
	}

	size, err := core.GetTerminalSize()
	if err != nil {
		return err
	}
	if size.WidthPx == 0 || size.HeightPx == 0 {
		// If we're unable to get the terminal dimensions in pixels,
		// render the image using blocks.
		return writeBlocksTo(img, size.Cols, size.Rows, dst)
	}

	switch detectEmulator().Protocol() {
	case protoInline:
		return writeInlineTo(img, size.WidthPx, size.HeightPx, dst)
	case protoKitty:
		return writeKittyTo(img, size.WidthPx, size.HeightPx, dst)
	default:
		return writeBlocksTo(img, size.Cols, size.Rows, dst)
	}
}

var errImageDimensions = errors.New("image dimensions rejected")

func decodeImage(ctx context.Context, b []byte, mode core.ImageSetting) (image.Image, error) {
	img, err := decodeImageStd(b)
	if err == nil {
		return img, nil
	}
	// Do not let an adapter bypass the raster safety boundary. Adapters may
	// convert an unsupported format, but they may not rescue an image whose
	// declared dimensions or allocation arithmetic is already unsafe.
	if errors.Is(err, errImageDimensions) {
		return nil, err
	}

	// ImageAuto is intentionally not the same as ImageExternal. Automatic
	// rendering must never start a process based on a server-supplied image.
	if mode != core.ImageExternal {
		return nil, err
	}

	img, adapterErr := decodeWithAdaptors(ctx, b)
	if adapterErr == nil {
		return img, nil
	}
	return nil, fmt.Errorf("unable to decode image: built-in decoder: %v; %w", err, adapterErr)
}

const maxImageDimension = 8192

func decodeImageStd(b []byte) (image.Image, error) {
	config, _, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	if err := validateImageConfig(config); err != nil {
		return nil, err
	}

	img, _, err := image.Decode(bytes.NewReader(b))
	return img, err
}

func validateImageConfig(config image.Config) error {
	width, height := config.Width, config.Height
	if width <= 0 || height <= 0 {
		return fmt.Errorf("%w: invalid %dx%d", errImageDimensions, width, height)
	}
	if width > maxImageDimension || height > maxImageDimension {
		return fmt.Errorf("%w: image dimensions are too large %dx%d (maximum %dx%d)", errImageDimensions, width, height, maxImageDimension, maxImageDimension)
	}

	// DecodeConfig runs before the full raster decode. Check the largest
	// common allocation here so a malformed header cannot wrap a pixel or
	// stride calculation on a 32-bit build.
	pixels, ok := core.CheckedMulInt(width, height)
	if !ok {
		return fmt.Errorf("%w: pixel allocation overflows for %dx%d", errImageDimensions, width, height)
	}
	if _, ok := core.CheckedMulInt(pixels, 4); !ok {
		return fmt.Errorf("%w: pixel allocation overflows for %dx%d", errImageDimensions, width, height)
	}
	if _, ok := core.CheckedMulInt(width, 4); !ok {
		return fmt.Errorf("%w: pixel stride overflows for %dx%d", errImageDimensions, width, height)
	}
	return nil
}

// resizeForTerm returns a new image that has been resized to fit in less than
// 80% of the terminal height. All products are checked before they are used
// as allocation sizes. Terminal dimensions are external input on some
// platforms and must not be allowed to wrap.
func resizeForTerm(img image.Image, termWidthPx, termHeightPx int) image.Image {
	if termWidthPx <= 0 || termHeightPx <= 0 {
		return img
	}

	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width <= 0 || height <= 0 {
		return img
	}
	maxWidth := minPositive(termWidthPx, width)
	maxHeight := boundedScale(termHeightPx, 4, 5, height)
	width, height = fitImage(width, height, maxWidth, maxHeight)
	if width == bounds.Dx() && height == bounds.Dy() {
		return img
	}
	return resizeImage(img, width, height)
}

func minPositive(value, limit int) int {
	if value <= 0 {
		return 1
	}
	if limit > 0 && value > limit {
		return limit
	}
	return value
}

func boundedScale(value, numerator, denominator, limit int) int {
	if value <= 0 || numerator <= 0 || denominator <= 0 || limit <= 0 {
		return 1
	}
	product, ok := core.CheckedMulInt(value, numerator)
	if !ok {
		return limit
	}
	scaled := product / denominator
	if scaled < 1 {
		return 1
	}
	if scaled > limit {
		return limit
	}
	return scaled
}

func fitImage(width, height, maxWidth, maxHeight int) (int, int) {
	if width <= 0 || height <= 0 || maxWidth <= 0 || maxHeight <= 0 {
		return 1, 1
	}
	if width <= maxWidth && height <= maxHeight {
		return width, height
	}
	widthRatio := float64(maxWidth) / float64(width)
	heightRatio := float64(maxHeight) / float64(height)
	scale := min(widthRatio, heightRatio)
	newWidth := boundedFloatDimension(float64(width)*scale, maxWidth)
	newHeight := boundedFloatDimension(float64(height)*scale, maxHeight)
	return newWidth, newHeight
}

func boundedFloatDimension(value float64, limit int) int {
	if math.IsNaN(value) || value <= 1 {
		return 1
	}
	if math.IsInf(value, 1) || value >= float64(limit) {
		return limit
	}
	result := int(value)
	if result < 1 {
		return 1
	}
	if result > limit {
		return limit
	}
	return result
}

// resizeImage returns a new image that has been scaled to the provided width
// and height. Invalid or overflowing sizes leave the original image intact.
func resizeImage(img image.Image, width, height int) image.Image {
	if width <= 0 || height <= 0 {
		return img
	}
	pixels, ok := core.CheckedMulInt(width, height)
	if !ok {
		return img
	}
	if _, ok := core.CheckedMulInt(pixels, 4); !ok {
		return img
	}
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
