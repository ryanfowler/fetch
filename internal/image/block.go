package image

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"os"
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

// supportsTrueColor checks the COLORTERM environment variable.
func supportsTrueColor() bool {
	ct := os.Getenv("COLORTERM")
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "truecolor") || strings.Contains(ct, "24bit")
}

// ansiFG returns the ANSI escape code for setting the foreground color.
func ansiFG(c *rgbColor, trueColor bool) string {
	if c == nil {
		return ""
	}
	if trueColor {
		return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", c.r, c.g, c.b)
	}
	return fmt.Sprintf("\x1b[38;5;%dm", ansi256FromRGB(uint8(c.r), uint8(c.g), uint8(c.b)))
}

// ansiBG returns the ANSI escape code for setting the background color.
func ansiBG(c *rgbColor, trueColor bool) string {
	if c == nil {
		return ""
	}
	if trueColor {
		return fmt.Sprintf("\x1b[48;2;%d;%d;%dm", c.r, c.g, c.b)
	}
	return fmt.Sprintf("\x1b[48;5;%dm", ansi256FromRGB(uint8(c.r), uint8(c.g), uint8(c.b)))
}

// ansi256FromRGB converts an RGB triplet to an ANSI 256 color index.
func ansi256FromRGB(r, g, b uint8) int {
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
	red := int(r) * 5 / 255
	green := int(g) * 5 / 255
	blue := int(b) * 5 / 255
	return 16 + 36*red + 6*green + blue
}

// pixelToColor converts a color.Color into a *Color (or nil if fully transparent).
func pixelToColor(c color.Color) *rgbColor {
	r, g, b, a := c.RGBA()
	if a == 0 {
		return nil
	}
	// RGBA returns values in [0, 65535]; shift down to 8 bits.
	return &rgbColor{int(r >> 8), int(g >> 8), int(b >> 8)}
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
		h := (height * cols) / width / 2
		if h < 1 {
			h = 1
		}
		return cols, h
	}

	w := (width * rows) / height
	h := rows / 2
	if h < 1 {
		h = 1
	}
	return w, h
}

// writeBlocks resizes the image and outputs it as terminal blocks.
func writeBlocks(img image.Image, termWidth, termHeight int) error {
	trueColor := supportsTrueColor()

	cols, rows := imageBlockOutputDimensions(img, termWidth, termHeight)

	// Each terminal block represents 2 vertical pixels.
	targetWidth := cols
	targetHeight := rows * 2

	dst := resizeImage(img, targetWidth, targetHeight)

	// Process the image in blocks (each block = two vertical pixels).
	var out bytes.Buffer
	for row := 0; row < rows; row++ {
		topY := row * 2
		bottomY := topY + 1

		for x := 0; x < cols; x++ {
			top := pixelToColor(dst.At(x, topY))
			var bottom *rgbColor
			if bottomY < targetHeight {
				bottom = pixelToColor(dst.At(x, bottomY))
			}

			block := computeBlock(top, bottom, trueColor)
			out.WriteString(block)
		}
		out.WriteString("\n")
	}

	// Reset ANSI formatting at the end.
	out.WriteString("\x1b[0m")
	_, err := os.Stdout.Write(out.Bytes())
	return err
}

// computeBlock returns the ANSI-coded string for one block given the top and bottom pixel colors.
func computeBlock(top, bottom *rgbColor, trueColor bool) string {
	// Both parts transparent.
	if top == nil && bottom == nil {
		return " "
	}

	var esc string
	var ch string

	// If there is no bottom pixel (or it's transparent), use the upper half block.
	if bottom == nil {
		esc = ansiFG(top, trueColor)
		ch = upperHalfBlock
	} else if top == nil {
		// Only bottom has color.
		esc = ansiFG(bottom, trueColor)
		ch = lowerHalfBlock
	} else {
		// Both have a color: use lower half block with top as background and bottom as foreground.
		esc = ansiBG(top, trueColor) + ansiFG(bottom, trueColor)
		ch = lowerHalfBlock
	}
	// Reset after this block.
	return esc + ch + "\x1b[0m"
}
