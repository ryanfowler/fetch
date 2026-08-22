package image

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func pngBytes(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeImageAutoDoesNotUseExternalAdapters(t *testing.T) {
	data := pngBytes(t, 2, 3)
	img, err := decodeImage(context.Background(), data, core.ImageAuto)
	if err != nil {
		t.Fatalf("decodeImage() error = %v", err)
	}
	if got := img.Bounds().Size(); got.X != 2 || got.Y != 3 {
		t.Fatalf("decoded size = %v, want 2x3", got)
	}
}

func TestDecodeImageExternalUsesAdaptersOnlyWhenExplicit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test adapter uses a POSIX script")
	}
	adapterDir := t.TempDir()
	fixture := filepath.Join(adapterDir, "fixture.png")
	if err := os.WriteFile(fixture, pngBytes(t, 3, 2), 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(adapterDir, "called")
	script := filepath.Join(adapterDir, "vips")
	contents := "#!/bin/sh\ntouch \"$FETCH_IMAGE_TEST_MARKER\"\ncp \"$FETCH_IMAGE_TEST_FIXTURE\" \"$3\"\n"
	if err := os.WriteFile(script, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}
	headerScript := filepath.Join(adapterDir, "vipsheader")
	if err := os.WriteFile(headerScript, []byte("#!/bin/sh\nprintf '1\\n1\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FETCH_IMAGE_TEST_MARKER", marker)
	t.Setenv("FETCH_IMAGE_TEST_FIXTURE", fixture)
	t.Setenv("PATH", adapterDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if _, err := decodeImage(context.Background(), []byte("not an image"), core.ImageAuto); err == nil {
		t.Fatal("auto mode unexpectedly decoded an unsupported image")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("auto mode ran an adapter; marker stat error = %v", err)
	}
	img, err := decodeImage(context.Background(), []byte("not an image"), core.ImageExternal)
	if err != nil {
		t.Fatalf("external mode error = %v", err)
	}
	if got := img.Bounds().Size(); got.X != 3 || got.Y != 2 {
		t.Fatalf("external decoded size = %v, want 3x2", got)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("external adapter was not run: %v", err)
	}
}

func TestValidateImageConfig(t *testing.T) {
	for _, test := range []struct {
		name string
		cfg  image.Config
		want string
	}{
		{name: "zero width", cfg: image.Config{Width: 0, Height: 1}, want: "invalid"},
		{name: "zero height", cfg: image.Config{Width: 1, Height: 0}, want: "invalid"},
		{name: "too wide", cfg: image.Config{Width: maxImageDimension + 1, Height: 1}, want: "too large"},
		{name: "too high", cfg: image.Config{Width: 1, Height: maxImageDimension + 1}, want: "too large"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateImageConfig(test.cfg); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateImageConfig() error = %v, want %q", err, test.want)
			}
		})
	}
}

type boundsOnlyImage struct{ bounds image.Rectangle }

func (i boundsOnlyImage) ColorModel() color.Model { return color.RGBAModel }
func (i boundsOnlyImage) Bounds() image.Rectangle { return i.bounds }
func (i boundsOnlyImage) At(int, int) color.Color { return color.Transparent }

func TestImageOutputDimensionsRemainBounded(t *testing.T) {
	img := boundsOnlyImage{bounds: image.Rect(0, 0, 8192, 8192)}
	width, height := imageBlockOutputDimensions(img, int(^uint(0)>>1), int(^uint(0)>>1))
	if width <= 0 || height <= 0 || width > 8192 || height > 4096 {
		t.Fatalf("block dimensions = %dx%d, outside source bounds", width, height)
	}
}

func TestCappedOutput(t *testing.T) {
	var output cappedOutput
	output.max = 3
	if n, err := output.Write([]byte("abcd")); n != 3 || err == nil {
		t.Fatalf("first capped write = %d, %v; want 3 and an error", n, err)
	}
	if !output.limitHit() || output.Len() != 3 {
		t.Fatalf("capped output state = hit %v, len %d", output.limitHit(), output.Len())
	}
}
