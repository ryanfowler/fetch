package image

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"io"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func gifBytes(t testing.TB, frames int) []byte {
	t.Helper()
	palette := color.Palette{color.Transparent, color.RGBA{R: 255, A: 255}, color.RGBA{B: 255, A: 255}}
	g := &gif.GIF{
		Config:    image.Config{ColorModel: palette, Width: 3, Height: 2},
		LoopCount: 2,
	}
	for i := range frames {
		// The first frame has an offset; the second uses a local palette.
		p := palette
		if i%2 == 1 {
			p = color.Palette{color.Transparent, color.RGBA{G: 255, A: 255}}
		}
		frame := image.NewPaletted(image.Rect(1, 0, 3, 2), p)
		frame.SetColorIndex(1, 0, 1)
		g.Image = append(g.Image, frame)
		g.Delay = append(g.Delay, i*20)
		g.Disposal = append(g.Disposal, byte(i%3+1))
	}
	var out bytes.Buffer
	if err := gif.EncodeAll(&out, g); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestGIFBuiltInStill(t *testing.T) {
	for _, mode := range []core.ImageSetting{core.ImageAuto, core.ImageNative, core.ImageExternal} {
		img, err := decodeImage(context.Background(), gifBytes(t, 2), mode)
		if err != nil {
			t.Fatal(err)
		}
		if img.Bounds() != image.Rect(0, 0, 3, 2) {
			t.Fatalf("canvas bounds = %v", img.Bounds())
		}
		if got := color.RGBAModel.Convert(img.At(1, 0)); got != (color.RGBA{R: 255, A: 255}) {
			t.Fatalf("first frame pixel = %v", got)
		}
		if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
			t.Fatal("transparent canvas became opaque")
		}
	}
}

func TestGIFOpaqueBackground(t *testing.T) {
	palette := color.Palette{color.RGBA{B: 255, A: 255}, color.RGBA{R: 255, A: 255}}
	frame := image.NewPaletted(image.Rect(1, 0, 2, 1), palette)
	frame.SetColorIndex(1, 0, 1)
	g := &gif.GIF{
		Config: image.Config{ColorModel: palette, Width: 2, Height: 1},
		Image:  []*image.Paletted{frame}, Delay: []int{0},
	}
	var b bytes.Buffer
	if err := gif.EncodeAll(&b, g); err != nil {
		t.Fatal(err)
	}
	img, err := decodeImageStd(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img.At(0, 0)); got != (color.RGBA{B: 255, A: 255}) {
		t.Fatalf("background = %v", got)
	}
}

func TestGIFAnimationSanitizesAndPreservesFrames(t *testing.T) {
	data := gifBytes(t, 3)
	// Comments and trailing bytes must not reach the terminal's image parser.
	comment := []byte("\x1b]52;c;attack\x07")
	extension := append([]byte{0x21, 0xfe, byte(len(comment))}, comment...)
	extension = append(extension, 0)
	extension = append(extension, 0x21, 0xff, 11)
	extension = append(extension, []byte("UNTRUSTED!!")...)
	extension = append(extension, byte(len(comment)))
	extension = append(extension, comment...)
	extension = append(extension, 0)
	data = append(append(append([]byte{}, data[:len(data)-1]...), extension...), 0x3b)
	data = append(data, []byte("TRAILING-SECRET")...)
	encoded, err := encodeGIFAnimation(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, comment) || bytes.Contains(encoded, []byte("UNTRUSTED!!")) || bytes.Contains(encoded, []byte("TRAILING-SECRET")) {
		t.Fatal("untrusted metadata survived re-encoding")
	}
	original, err := gif.DecodeAll(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	clean, err := gif.DecodeAll(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.Image) != 3 || clean.LoopCount != original.LoopCount || clean.Config.Width != 3 || clean.Config.Height != 2 {
		t.Fatalf("animation changed: %+v", clean)
	}
	for i, frame := range clean.Image {
		if frame.Bounds() != original.Image[i].Bounds() || !bytes.Equal(frame.Pix, original.Image[i].Pix) || clean.Disposal[i] != original.Disposal[i] {
			t.Fatalf("frame %d changed", i)
		}
		for y := frame.Rect.Min.Y; y < frame.Rect.Max.Y; y++ {
			for x := frame.Rect.Min.X; x < frame.Rect.Max.X; x++ {
				if frame.At(x, y) != original.Image[i].At(x, y) {
					t.Fatalf("frame %d palette changed", i)
				}
			}
		}
		if clean.Delay[i] != max(original.Delay[i], minGIFDelay) {
			t.Fatalf("frame %d delay = %d", i, clean.Delay[i])
		}
	}
}

func inlinePayload(t *testing.T, output string) []byte {
	t.Helper()
	start := strings.IndexByte(output, ':')
	if start < 0 || !strings.HasPrefix(output, "\x1b]1337;File=inline=1;") || !strings.HasSuffix(output, "\x07\n") {
		t.Fatalf("invalid inline output: %q", output)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(output[start+1:], "\x07\n"))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestGIFInlineAnimationAndStillFallback(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
		want string
	}{
		{"animated", gifBytes(t, 2), "gif"},
		{"single frame", gifBytes(t, 1), "png"},
		{"too many frames", gifBytes(t, maxGIFAnimationFrames+1), "png"},
		{"truncated later frame", gifBytes(t, 2)[:len(gifBytes(t, 2))-5], "png"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			still, err := decodeImageStd(tt.data)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := writeGIFInlineTo(context.Background(), tt.data, still, 2, 2, &out); err != nil {
				t.Fatal(err)
			}
			_, format, err := image.Decode(bytes.NewReader(inlinePayload(t, out.String())))
			if err != nil || format != tt.want {
				t.Fatalf("format = %q, error = %v; want %q", format, err, tt.want)
			}
			if tt.want == "gif" && !strings.Contains(out.String(), "width=1px;height=1px:") {
				t.Fatalf("animation not fitted to terminal: %q", out.String())
			}
		})
	}
}

func TestGIFAnimationBudgets(t *testing.T) {
	valid := gifBytes(t, 2)
	largeCanvas := bytes.Clone(valid)
	binary.LittleEndian.PutUint16(largeCanvas[6:8], 4096)
	binary.LittleEndian.PutUint16(largeCanvas[8:10], 4096)
	oversized := bytes.Clone(valid)
	binary.LittleEndian.PutUint16(oversized[6:8], 65535)
	zero := bytes.Clone(valid)
	binary.LittleEndian.PutUint16(zero[6:8], 0)
	invalidFrame := bytes.Clone(valid)
	descriptor := bytes.IndexByte(invalidFrame, 0x2c)
	if descriptor < 0 {
		t.Fatal("fixture has no image descriptor")
	}
	binary.LittleEndian.PutUint16(invalidFrame[descriptor+5:descriptor+7], 65535)
	for _, data := range [][]byte{
		gifBytes(t, maxGIFAnimationFrames+1), largeCanvas, oversized, zero, invalidFrame,
		append(bytes.Clone(valid), make([]byte, maxGIFAnimationBytes)...),
		[]byte("GIF89a"), valid[:13], valid[:len(valid)-1],
	} {
		if _, err := checkGIFAnimation(context.Background(), data); err == nil {
			t.Fatal("unsafe animation accepted")
		}
	}
	if _, err := decodeImage(context.Background(), oversized, core.ImageExternal); !errors.Is(err, errImageDimensions) {
		t.Fatalf("oversized GIF error = %v", err)
	}
	// A huge canvas with tiny changed rectangles must use the still fallback.
	still, err := decodeImageStd(largeCanvas)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeGIFInlineTo(context.Background(), largeCanvas, still, 3, 3, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(inlinePayload(t, out.String()), []byte("\x89PNG")) {
		t.Fatal("large canvas did not fall back to PNG")
	}
}

func TestGIFCancellationAndWriteErrors(t *testing.T) {
	data := gifBytes(t, 2)
	still, err := decodeImageStd(data)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if err := writeGIFInlineTo(ctx, data, still, 80, 80, &out); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatalf("cancelled output: len %d, error %v", out.Len(), err)
	}
	if _, err := decodeImage(ctx, data, core.ImageAuto); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled decode error = %v", err)
	}
	if err := writeGIFInlineTo(context.Background(), data, still, 80, 80, gifErrorWriter{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("destination error = %v", err)
	}
	w := &gifAnimationOutput{ctx: context.Background()}
	if _, err := w.Write(make([]byte, maxGIFAnimationBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte{0}); !errors.Is(err, errGIFAnimation) {
		t.Fatalf("output limit error = %v", err)
	}
}

type gifErrorWriter struct{}

func (gifErrorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func FuzzGIFAnimationBudget(f *testing.F) {
	f.Add(gifBytes(f, 2))
	f.Add([]byte("GIF89a"))
	f.Fuzz(func(t *testing.T, data []byte) {
		frames, err := checkGIFAnimation(context.Background(), data)
		if err != nil {
			return
		}
		g, err := gif.DecodeAll(bytes.NewReader(data))
		if err != nil {
			return
		}
		if len(g.Image) != frames || frames > maxGIFAnimationFrames || int64(frames)*int64(g.Config.Width)*int64(g.Config.Height) > maxGIFAnimationPixels {
			t.Fatal("budget scan disagrees with standard decoder")
		}
	})
}
