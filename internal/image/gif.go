package image

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"io"
)

const (
	maxGIFAnimationBytes  = 8 << 20
	maxGIFAnimationFrames = 128
	// Charge the full canvas for every frame, not just its changed pixels.
	// This bounds both decoder storage and the terminal's compositing work.
	maxGIFAnimationPixels = 16 << 20
	minGIFDelay           = 10 // Hundredths of a second: at most 10 frames/s.
)

var errGIFAnimation = errors.New("GIF animation is invalid or exceeds safety limits")

func isGIF(b []byte) bool {
	return bytes.HasPrefix(b, []byte("GIF87a")) || bytes.HasPrefix(b, []byte("GIF89a"))
}

// gifStillCanvas places the first frame at its logical-screen offset. A GIF
// frame need not cover the whole screen. Transparent GIFs retain transparency;
// opaque GIFs use the declared background color when it is available.
func gifStillCanvas(b []byte, config image.Config, frame image.Image) image.Image {
	bounds := image.Rect(0, 0, config.Width, config.Height)
	if frame.Bounds() == bounds {
		return frame
	}
	canvas := image.NewRGBA(bounds)
	transparent := false
	if p, ok := frame.ColorModel().(color.Palette); ok {
		for _, c := range p {
			_, _, _, a := c.RGBA()
			transparent = transparent || a == 0
		}
	}
	if p, ok := config.ColorModel.(color.Palette); ok && !transparent && len(b) > 11 && int(b[11]) < len(p) {
		draw.Draw(canvas, bounds, image.NewUniform(p[b[11]]), image.Point{}, draw.Src)
	}
	draw.Draw(canvas, frame.Bounds(), frame, frame.Bounds().Min, draw.Over)
	return canvas
}

// writeGIFInlineTo never forwards source bytes to the terminal. Decode and
// re-encode first to remove comments, application extensions, and trailing
// data. Any animation failure falls back to the already decoded first frame;
// cancellation and destination errors must instead reach the caller.
func writeGIFInlineTo(ctx context.Context, b []byte, still image.Image, termWidthPx, termHeightPx int, dst io.Writer) error {
	data, err := encodeGIFAnimation(ctx, b)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return writeInlineTo(still, termWidthPx, termHeightPx, dst)
	}
	bounds := still.Bounds()
	width, height := fitImage(bounds.Dx(), bounds.Dy(),
		minPositive(termWidthPx, bounds.Dx()), boundedScale(termHeightPx, 4, 5, bounds.Dy()))
	_, err = fmt.Fprintf(dst, "\x1b]1337;File=inline=1;preserveAspectRatio=1;size=%d;width=%dpx;height=%dpx:%s\x07\n",
		len(data), width, height, base64.StdEncoding.EncodeToString(data))
	return err
}

func encodeGIFAnimation(ctx context.Context, b []byte) ([]byte, error) {
	// DecodeAll retains every frame. The structural budget pass must run
	// before it, even when the compressed input is very small.
	frames, err := checkGIFAnimation(ctx, b)
	if err != nil {
		return nil, err
	}
	if frames < 2 {
		return nil, errGIFAnimation
	}
	g, err := gif.DecodeAll(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	for i := range g.Delay {
		g.Delay[i] = max(g.Delay[i], minGIFDelay)
		if g.Disposal[i] > gif.DisposalPrevious {
			return nil, errGIFAnimation
		}
	}
	if p, ok := g.Config.ColorModel.(color.Palette); int(g.BackgroundIndex) >= len(p) || !ok {
		g.BackgroundIndex = 0
	}
	out := gifAnimationOutput{ctx: ctx}
	if err := gif.EncodeAll(&out, g); err != nil {
		return nil, err
	}
	return out.buf.Bytes(), nil
}

// checkGIFAnimation only walks block boundaries and allocation dimensions.
// The standard library remains responsible for validating and decoding GIF.
func checkGIFAnimation(ctx context.Context, b []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(b) > maxGIFAnimationBytes || len(b) < 13 || !isGIF(b) {
		return 0, errGIFAnimation
	}
	u16 := func(b []byte) int { return int(binary.LittleEndian.Uint16(b)) }
	width, height := u16(b[6:8]), u16(b[8:10])
	// Division avoids overflow, including on 32-bit builds.
	if width <= 0 || height <= 0 || width > maxImageDimension || height > maxImageDimension || width > maxGIFAnimationPixels/height {
		return 0, errGIFAnimation
	}
	canvasPixels := width * height
	tableSize := func(flags byte) int {
		if flags&0x80 == 0 {
			return 0
		}
		return 3 * (1 << (1 + (flags & 7)))
	}
	pos := 13 + tableSize(b[10])
	frames := 0
	for pos < len(b) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		block := b[pos]
		pos++
		switch block {
		case 0x3b: // Trailer.
			return frames, nil
		case 0x21: // Extension label, followed by sub-blocks.
			if pos >= len(b) {
				return 0, errGIFAnimation
			}
			pos++
		case 0x2c: // Image descriptor, optional palette, LZW code size.
			if len(b)-pos < 9 {
				return 0, errGIFAnimation
			}
			d := b[pos : pos+9]
			left, top, w, h := u16(d[:2]), u16(d[2:4]), u16(d[4:6]), u16(d[6:8])
			if w <= 0 || h <= 0 || left+w > width || top+h > height {
				return 0, errGIFAnimation
			}
			frames++
			if frames > maxGIFAnimationFrames || frames > maxGIFAnimationPixels/canvasPixels {
				return 0, errGIFAnimation
			}
			pos += 9 + tableSize(d[8]) + 1
		default:
			return 0, errGIFAnimation
		}
		// Skip extension or compressed image data, without allocating.
		for {
			if pos >= len(b) {
				return 0, errGIFAnimation
			}
			n := int(b[pos])
			pos++
			if n == 0 {
				break
			}
			if n > len(b)-pos {
				return 0, errGIFAnimation
			}
			pos += n
		}
	}
	return 0, errGIFAnimation
}

// Bound encoded output as well as decoded pixels. Check cancellation during
// encoding without exposing a partial terminal control sequence.
type gifAnimationOutput struct {
	ctx context.Context
	buf bytes.Buffer
}

func (w *gifAnimationOutput) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > maxGIFAnimationBytes-w.buf.Len() {
		return 0, errGIFAnimation
	}
	return w.buf.Write(p)
}
