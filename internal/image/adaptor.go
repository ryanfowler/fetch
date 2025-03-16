package image

import (
	"bytes"
	"context"
	"errors"
	"image"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
)

const imagePathArg = "IMAGE_PATH"

type adaptor struct {
	name string
	args []string
	env  []string
}

var adaptors = []adaptor{
	{
		name: "vips",
		args: []string{"copy", imagePathArg, ".jpeg"},
		env:  []string{"VIPS_MAX_MEM=512MB"},
	},
	{
		name: "magick",
		args: []string{imagePathArg, "-flatten", "-auto-orient", "jpeg:-"},
		env:  []string{"MAGICK_MEMORY_LIMIT=512MiB"},
	},
	{
		name: "ffmpeg",
		args: []string{"-i", imagePathArg, "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1"},
	},
}

func decodeWithAdaptors(ctx context.Context, b []byte) (image.Image, error) {
	// Write the image to a temporary file.
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	imgPath := filepath.Join(dir, "fetch-temp-image")
	err = os.WriteFile(imgPath, b, 0666)
	if err != nil {
		return nil, err
	}

	// Attempt each adaptor, stopping at the first successful one.
	for _, a := range adaptors {
		img, err := decodeAdaptor(ctx, imgPath, a)
		if err == nil {
			return img, nil
		}
	}
	return nil, errors.New("unable to decode image")
}

func decodeAdaptor(ctx context.Context, imgPath string, a adaptor) (image.Image, error) {
	path, err := exec.LookPath(a.name)
	if err != nil {
		// Adaptor not found locally, exit.
		return nil, err
	}

	// Replace "IMAGE_PATH" argument with the actual image path.
	args := slices.Clone(a.args)
	for i, arg := range args {
		if arg == imagePathArg {
			args[i] = imgPath
		}
	}

	// Run the command, collecting the result on stdout.
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	if len(a.env) > 0 {
		cmd.Env = append(slices.Clone(a.env), os.Environ()...)
	}
	cmd.Stdout = &stdout
	if err = cmd.Run(); err != nil {
		return nil, err
	}

	// Attempt to decode the adaptor output.
	return decodeImageStd(stdout.Bytes())
}
