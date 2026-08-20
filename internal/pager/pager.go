// Package pager selects and runs the user's configured terminal pager.
package pager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"unicode"

	"github.com/ryanfowler/fetch/internal/core"
)

// ShouldPage reports whether text should be sent through a pager.
func ShouldPage(mode core.PagerMode, stdoutTerminal, image bool) bool {
	if image {
		return false
	}
	if mode == core.PagerUnknown {
		mode = core.PagerAuto
	}
	switch mode {
	case core.PagerOn:
		return true
	case core.PagerAuto:
		return stdoutTerminal && !DisabledByEnv()
	default:
		return false
	}
}

// DisabledByEnv reports whether NO_PAGER is set. Its value is intentionally
// ignored, so NO_PAGER=0 has the same disabling effect as NO_PAGER=1.
func DisabledByEnv() bool {
	_, ok := os.LookupEnv("NO_PAGER")
	return ok
}

// WriteText writes text directly or through the selected pager.
func WriteText(data []byte, mode core.PagerMode, stdoutTerminal bool) error {
	return WriteTextContext(context.Background(), data, mode, stdoutTerminal)
}

// WriteTextContext is WriteText with a cancellation context for a pager
// process. It is used by metadata commands so Ctrl-C also terminates a
// blocked pager.
func WriteTextContext(ctx context.Context, data []byte, mode core.PagerMode, stdoutTerminal bool) error {
	return StreamContext(ctx, strings.NewReader(string(data)), mode, stdoutTerminal, false, os.Stdout)
}

// Stream writes a response to dst, using a pager when the selected mode calls
// for one. It never invokes a shell. This keeps PAGER arguments data rather
// than executable shell syntax.
func Stream(src io.Reader, mode core.PagerMode, stdoutTerminal, image bool, dst io.Writer) error {
	return StreamContext(context.Background(), src, mode, stdoutTerminal, image, dst)
}

// StreamContext is Stream with cancellation for the pager subprocess.
func StreamContext(ctx context.Context, src io.Reader, mode core.PagerMode, stdoutTerminal, image bool, dst io.Writer) error {
	if !ShouldPage(mode, stdoutTerminal, image) {
		_, err := io.Copy(dst, src)
		return err
	}

	command := CommandFromEnv(os.Getenv)
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(command.Program, command.Args...)
	configureProcess(cmd)
	cmd.Stdout = dst
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		if command.Fallback && errors.Is(err, exec.ErrNotFound) {
			return copyDirect(src, dst)
		}
		return fmt.Errorf("unable to start pager: %w", err)
	}

	copyDone := make(chan struct{})
	var copyErr, closeErr error
	go func() {
		_, copyErr = io.Copy(stdin, src)
		closeErr = stdin.Close()
		close(copyDone)
	}()

	select {
	case <-copyDone:
	case <-ctx.Done():
		_ = stdin.Close()
		terminateProcessTree(cmd)
		<-copyDone
		return ctx.Err()
	}

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-ctx.Done():
		terminateProcessTree(cmd)
		<-waitDone
		return ctx.Err()
	}
	if copyErr != nil && !core.IsBrokenPipe(copyErr) {
		return copyErr
	}
	if closeErr != nil && !core.IsBrokenPipe(closeErr) {
		return closeErr
	}
	if waitErr != nil {
		// A broken pipe is harmless only when the pager itself exited
		// successfully. Preserve failures from a pager that closed its
		// input and then reported an error.
		return fmt.Errorf("pager exited unsuccessfully: %w", waitErr)
	}
	return nil
}

func copyDirect(src io.Reader, dst io.Writer) error {
	_, err := io.Copy(dst, src)
	return err
}

// Command describes a pager executable and its arguments.
type Command struct {
	Program  string
	Args     []string
	Fallback bool
}

// CommandFromEnv parses PAGER without invoking a shell. Invalid or empty PAGER
// values use the less fallback, matching the command's safe default.
func CommandFromEnv(getenv func(string) string) Command {
	if value, ok := lookupEnv(getenv, "PAGER"); ok {
		if words, err := splitWords(value); err == nil && len(words) > 0 {
			return Command{Program: words[0], Args: words[1:]}
		}
	}

	command := Command{Program: "less", Fallback: true}
	if _, ok := lookupEnv(getenv, "LESS"); !ok {
		command.Args = []string{"-FIRX"}
	}
	return command
}

// lookupEnv lets tests use os.Getenv while retaining the distinction between
// an unset variable and an explicitly empty one.
func lookupEnv(getenv func(string) string, name string) (string, bool) {
	if getenv == nil {
		return "", false
	}
	value := getenv(name)
	// os.Getenv cannot distinguish unset from empty. An empty value is not a
	// useful pager command in either case, so treating it as unset is safe.
	return value, value != ""
}

// splitWords is a small POSIX-style word parser for PAGER. Quotes and
// backslashes group characters; operators such as | and ; remain ordinary
// argument characters and can never become shell syntax.
func splitWords(input string) ([]string, error) {
	var words []string
	var word strings.Builder
	inWord := false
	quote := byte(0)
	escaped := false

	flush := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}

	for i := 0; i < len(input); i++ {
		c := input[i]
		if escaped {
			word.WriteByte(c)
			inWord = true
			escaped = false
			continue
		}
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				word.WriteByte(c)
				inWord = true
			}
			continue
		}
		if quote == '"' {
			switch c {
			case '"':
				quote = 0
			case '\\':
				escaped = true
			default:
				word.WriteByte(c)
				inWord = true
			}
			continue
		}

		switch {
		case c == '\\':
			escaped = true
			inWord = true
		case c == '\'' || c == '"':
			quote = c
			inWord = true
		case unicode.IsSpace(rune(c)):
			flush()
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	if escaped || quote != 0 {
		return nil, errors.New("unterminated pager quoting")
	}
	flush()
	return words, nil
}
