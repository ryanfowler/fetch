package image

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"io"
	"os"
	"runtime"
	"strings"
)

const (
	upperHalfBlock = "\u2580" // Unicode: upper half block
	lowerHalfBlock = "\u2584" // Unicode: lower half block
)

// rgbColor holds 8-bit RGB values.
type rgbColor struct {
	r, g, b int
}

func writeBlocksTo(img image.Image, termWidth, termHeight int, writer io.Writer) error {
	trueColor := supportsTrueColor()

	// Each terminal block represents 2 vertical pixels.
	cols, rows := imageBlockOutputDimensions(img, termWidth, termHeight)
	targetWidth := cols
	targetHeight := rows * 2

	raster := resizeImage(img, targetWidth, targetHeight)

	// Process the image in blocks (each block = two vertical pixels).
	var out bytes.Buffer
	for row := range rows {
		topY := row * 2
		bottomY := topY + 1

		for x := range cols {
			top := pixelToColor(raster.At(x, topY))
			var bottom *rgbColor
			if bottomY < targetHeight {
				bottom = pixelToColor(raster.At(x, bottomY))
			}

			writeBlock(&out, top, bottom, trueColor)
		}
		out.WriteString("\n")
	}

	// Reset ANSI formatting at the end.
	out.WriteString("\x1b[0m")
	_, err := out.WriteTo(writer)
	return err
}

// supportsTrueColor checks the current terminal emulator for true color support.
func supportsTrueColor() bool {
	ct := os.Getenv("COLORTERM")
	if strings.EqualFold(ct, "truecolor") || strings.EqualFold(ct, "24bit") {
		return true
	}

	if runtime.GOOS == "windows" {
		return os.Getenv("WT_SESSION") != "" || os.Getenv("ConEmuANSI") == "ON"
	}

	return false
}

// imageBlockOutputDimensions returns the desired number of block columns and rows.
// (Each block represents two vertical pixels.) It uses checked scaling because
// terminal dimensions are not trusted allocation inputs.
func imageBlockOutputDimensions(img image.Image, termWidth, termHeight int) (int, int) {
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width <= 0 || height <= 0 {
		return 1, 1
	}
	if termWidth <= 0 || termHeight <= 0 {
		return 1, 1
	}

	cols := minPositive(termWidth, width)
	pixelHeight := boundedScale(termHeight, 8, 5, height)
	targetWidth, targetHeight := fitImage(width, height, cols, pixelHeight)
	return targetWidth, max((targetHeight+1)/2, 1)
}

// pixelToColor converts a color.Color into a *rgbColor (or nil if fully transparent).
func pixelToColor(c color.Color) *rgbColor {
	r, g, b, a := c.RGBA()
	if a == 0 {
		return nil
	}
	// RGBA returns values in [0, 65535]; shift down to 8 bits.
	return &rgbColor{int(r >> 8), int(g >> 8), int(b >> 8)}
}

// writeBlock writes the ANSI-coded string for one block given the top and
// bottom pixel colors.
func writeBlock(buf *bytes.Buffer, top, bottom *rgbColor, trueColor bool) {
	// Both parts transparent.
	if top == nil && bottom == nil {
		buf.WriteString(" ")
		return
	}

	// If there is no bottom pixel (or it's transparent), use the upper half block.
	var ch string
	if bottom == nil {
		ansiFG(buf, top, trueColor)
		ch = upperHalfBlock
	} else if top == nil {
		// Only bottom has color.
		ansiFG(buf, bottom, trueColor)
		ch = lowerHalfBlock
	} else {
		// Both have a color: use lower half block with top as background and bottom as foreground.
		ansiBG(buf, top, trueColor)
		ansiFG(buf, bottom, trueColor)
		ch = lowerHalfBlock
	}
	// Reset after this block.
	buf.WriteString(ch)
	buf.WriteString("\x1b[0m")
}

// ansiFG returns the ANSI escape code for setting the foreground color.
func ansiFG(w io.Writer, c *rgbColor, trueColor bool) {
	if c == nil {
		return
	}
	if trueColor {
		fmt.Fprintf(w, "\x1b[38;2;%d;%d;%dm", c.r, c.g, c.b)
	} else {
		fmt.Fprintf(w, "\x1b[38;5;%dm", ansi256FromRGB(c.r, c.g, c.b))
	}
}

// ansiBG returns the ANSI escape code for setting the background color.
func ansiBG(w io.Writer, c *rgbColor, trueColor bool) {
	if c == nil {
		return
	}
	if trueColor {
		fmt.Fprintf(w, "\x1b[48;2;%d;%d;%dm", c.r, c.g, c.b)
	} else {
		fmt.Fprintf(w, "\x1b[48;5;%dm", ansi256FromRGB(c.r, c.g, c.b))
	}
}

// ansi256FromRGB converts an RGB triplet to an ANSI 256 color index.
func ansi256FromRGB(r, g, b int) int {
	// Grayscale range.
	if r == g && g == b {
		if r < 8 {
			return 16
		}
		if r > 248 {
			return 231
		}
		return int((float64(r)-8)/10.0) + 232
	}
	red := r * 5 / 255
	green := g * 5 / 255
	blue := b * 5 / 255
	return 16 + 36*red + 6*green + blue
}
