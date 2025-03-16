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

	"golang.org/x/term"
)

const (
	upperHalfBlock = "\u2580" // Unicode: upper half block
	lowerHalfBlock = "\u2584" // Unicode: lower half block
)

// rgbColor holds 8-bit RGB values.
type rgbColor struct {
	r, g, b int
}

// writeBlocks resizes the image and outputs it as terminal blocks.
func writeBlocks(img image.Image) error {
	trueColor := supportsTrueColor()

	termWidth, termHeight, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return err
	}
	cols, rows := imageBlockOutputDimensions(img, termWidth, termHeight)

	// Each terminal block represents 2 vertical pixels.
	targetWidth := cols
	targetHeight := rows * 2

	dst := resizeImage(img, targetWidth, targetHeight)

	// Process the image in blocks (each block = two vertical pixels).
	var out bytes.Buffer
	for row := range rows {
		topY := row * 2
		bottomY := topY + 1

		for x := range cols {
			top := pixelToColor(dst.At(x, topY))
			var bottom *rgbColor
			if bottomY < targetHeight {
				bottom = pixelToColor(dst.At(x, bottomY))
			}

			writeBlock(&out, top, bottom, trueColor)
		}
		out.WriteString("\n")
	}

	// Reset ANSI formatting at the end.
	out.WriteString("\x1b[0m")
	out.WriteTo(os.Stdout)
	return nil
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
// (Each block represents two vertical pixels.)
func imageBlockOutputDimensions(img image.Image, termWidth, termHeight int) (int, int) {
	// Use only 4/5ths of the terminal height.
	cols := termWidth
	rows := 2 * termHeight * 4 / 5

	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	// If image is smaller than bounds, return the scaled image dimensions.
	if width <= cols && height <= rows {
		return width, height/2 + height%2
	}

	// Otherwise calculate appropriate size.
	if cols*height <= width*rows {
		return cols, max((height*cols)/width/2, 1)
	}

	return (width * rows) / height, max(rows/2, 1)
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
