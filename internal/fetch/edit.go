package fetch

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ryanfowler/fetch/internal/body"
	"github.com/ryanfowler/fetch/internal/core"
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
	defer func() { os.Remove(f.Name()) }()
	path, err := filepath.Abs(f.Name())
	if err != nil {
		return err
	}

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
	argv := append(editor, path)
	cmd := exec.Command(argv[0], argv[1:]...)
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
	edited, err := os.Open(path)
	if err != nil {
		return err
	}
	defer edited.Close()
	buf, err := core.ReadAllLimited(edited, core.MaxCompositeMaterialization, "edited request body")
	if err != nil {
		return err
	}

	// Abort the request if the file is empty.
	if len(buf) == 0 {
		return errors.New("aborting request due to empty request body after editing")
	}

	// Replace the source as well as http.Request's fields. Otherwise retry,
	// Digest, or dry-run would consult the pre-edit source in the context.
	body.Attach(req, body.NewBytes(buf, req.Header.Get("Content-Type")))
	return nil
}

func findEditor() ([]string, bool) {
	for _, env := range [...]string{"VISUAL", "EDITOR"} {
		if val := os.Getenv(env); val != "" {
			args := parseEditorArgs(val)
			if len(args) > 0 {
				return args, true
			}
		}
	}

	for _, v := range [...]string{"vim", "vi", "nano", "notepad.exe"} {
		path, err := exec.LookPath(v)
		if err == nil {
			return []string{path}, true
		}
	}
	return nil, false
}

func parseEditorArgs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	if _, err := exec.LookPath(s); err == nil {
		return []string{s}
	}

	if args, ok := parseEditorExecutablePrefix(s); ok {
		return args
	}

	return splitArgs(s)
}

func parseEditorExecutablePrefix(s string) ([]string, bool) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != ' ' && s[i] != '\t' {
			continue
		}
		name := strings.TrimSpace(s[:i])
		if name == "" {
			continue
		}
		if _, err := exec.LookPath(name); err != nil {
			continue
		}

		args := []string{name}
		args = append(args, splitArgs(s[i+1:])...)
		return args, true
	}
	return nil, false
}

// splitArgs splits a string into arguments, respecting single and double
// quotes. This is used to parse $EDITOR/$VISUAL values like "code --wait".
func splitArgs(s string) []string {
	var args []string
	var cur []byte
	i := 0
	for i < len(s) {
		ch := s[i]
		switch {
		case ch == ' ' || ch == '\t':
			if len(cur) > 0 {
				args = append(args, string(cur))
				cur = cur[:0]
			}
			i++
		case ch == '\'' || ch == '"':
			quote := ch
			i++
			for i < len(s) && s[i] != quote {
				cur = append(cur, s[i])
				i++
			}
			if i < len(s) {
				i++ // skip closing quote
			}
		default:
			cur = append(cur, ch)
			i++
		}
	}
	if len(cur) > 0 {
		args = append(args, string(cur))
	}
	return args
}
