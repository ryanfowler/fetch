package fetch

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

func edit(input io.Reader, extension string) ([]byte, error) {
	editor, ok := getEditor()
	if !ok {
		return nil, errors.New("unable to find an editor")
	}

	name := "fetch.*" + extension
	f, err := os.CreateTemp("", name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	path, err := filepath.Abs(f.Name())
	if err != nil {
		return nil, err
	}
	defer func() { os.Remove(path) }()

	if input != nil {
		_, err = io.Copy(f, input)
		if err == nil {
			_, err = f.Seek(0, 0)
		}
		if err != nil {
			return nil, err
		}
	}

	if err = f.Close(); err != nil {
		return nil, err
	}

	cmd := exec.Command(editor, path)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err = cmd.Run(); err != nil {
		if state := cmd.ProcessState; state != nil {
			code := state.ExitCode()
			return nil, fmt.Errorf("editor failed with exit code: %d", code)
		}
		return nil, fmt.Errorf("failed to start editor: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("aborting request due to empty body after editing")
	}

	return data, nil
}

func getEditor() (string, bool) {
	if visual := os.Getenv("VISUAL"); visual != "" {
		return visual, true
	}

	if editor := os.Getenv("EDITOR"); editor != "" {
		return editor, true
	}

	for _, v := range [...]string{"vim", "vi", "nano", "notepad.exe"} {
		path, err := exec.LookPath(v)
		if err == nil {
			return path, true
		}
	}
	return "", false
}
