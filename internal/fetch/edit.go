package fetch

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// editRequestBody opens an editor and allows the user to modify the request
// body before sending.
func editRequestBody(req *http.Request) error {
	// Find an appropriate editor to use.
	editor, ok := findEditor()
	if !ok {
		return errors.New("unable to find an editor")
	}

	// If the request contains a known content-type, use that as a file
	// extension for a better editing experience.
	var extension string
	switch req.Header.Get("Content-Type") {
	case "application/json":
		extension = ".json"
	case "application/xml", "text/xml":
		extension = ".xml"
	}

	// Create a temporary file, and ensure it's removed on exit.
	name := "fetch.*" + extension
	f, err := os.CreateTemp("", name)
	if err != nil {
		return err
	}
	defer f.Close()
	path, err := filepath.Abs(f.Name())
	if err != nil {
		return err
	}
	defer func() { os.Remove(path) }()

	// Copy any existing body to the temporary file before editing.
	input := req.Body
	if input != nil {
		_, err = io.Copy(f, input)
		if err != nil {
			return err
		}
		err = input.Close()
		if err != nil {
			return err
		}
	}
	if err = f.Close(); err != nil {
		return err
	}

	// Start the editor and block until completed.
	cmd := exec.Command(editor, path)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err = cmd.Run(); err != nil {
		if state := cmd.ProcessState; state != nil {
			code := state.ExitCode()
			return fmt.Errorf("editor failed with exit code: %d", code)
		}
		return fmt.Errorf("failed to start editor: %w", err)
	}

	// Read the file that was just modified.
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Abort the request if the file is empty.
	if len(buf) == 0 {
		return errors.New("aborting request due to empty request body after editing")
	}

	// Set the new body for the request.
	req.Body = io.NopCloser(bytes.NewReader(buf))
	req.ContentLength = int64(len(buf))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf)), nil
	}
	return nil
}

func findEditor() (string, bool) {
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
