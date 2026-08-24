// Package pager selects and runs the user's configured terminal pager.
package pager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"unicode"
	"unicode/utf8"

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
		return copyContext(ctx, src, dst)
	}

	command, err := commandFromLookup(os.LookupEnv)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(command.Program, command.Args...)
	// An interactive pager must remain in the terminal's foreground process
	// group. Otherwise it cannot receive keystrokes such as `q`; the parent
	// still owns the pager's data pipe, so the command appears to hang.
	if err := configureProcess(cmd, stdoutTerminal); err != nil {
		return fmt.Errorf("unable to configure pager: %w", err)
	}
	cmd.Stdout = dst
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		releaseProcess(cmd)
		return err
	}
	if err := cmd.Start(); err != nil {
		terminateProcessTree(cmd)
		if cmd.Process != nil {
			_ = cmd.Wait()
		}
		releaseProcess(cmd)
		return fmt.Errorf("unable to start pager: %w", err)
	}
	if err := attachProcess(cmd); err != nil {
		terminateProcessTree(cmd)
		_ = cmd.Wait()
		releaseProcess(cmd)
		return fmt.Errorf("unable to attach pager: %w", err)
	}
	defer releaseProcess(cmd)

	// A non-closable reader cannot be interrupted by this package. Keep its
	// copy synchronous so cancellation cannot strand a producer goroutine.
	// All response-body paths use closable readers, which take the concurrent
	// path below and can be stopped when the pager exits.
	if _, ok := src.(io.Closer); !ok {
		_, copyErr := io.Copy(stdin, src)
		_ = stdin.Close()
		waitDone := make(chan error, 1)
		go func() { waitDone <- cmd.Wait() }()
		select {
		case waitErr := <-waitDone:
			return pagerResult(copyErr, waitErr, false)
		case <-ctx.Done():
			terminateProcessTree(cmd)
			<-waitDone
			return ctx.Err()
		}
	}

	copyDone := make(chan copyResult, 1)
	go func() {
		_, copyErr := io.Copy(stdin, src)
		_ = stdin.Close()
		copyDone <- copyResult{copyErr: copyErr}
	}()

	// Wait concurrently with the producer. A pager such as `less` or `head`
	// may exit before the response body reaches EOF. Waiting for the producer
	// first would then keep a network response (and its goroutine) alive until
	// the remote peer closes it.
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	var result copyResult
	var waitErr error
	sourceClosed := false
	select {
	case result = <-copyDone:
		select {
		case waitErr = <-waitDone:
		case <-ctx.Done():
			closeReader(src)
			_ = stdin.Close()
			terminateProcessTree(cmd)
			<-waitDone
			return ctx.Err()
		}
	case waitErr = <-waitDone:
		sourceClosed = true
		closeReader(src)
		result = waitForCopy(copyDone)
	case <-ctx.Done():
		closeReader(src)
		_ = stdin.Close()
		terminateProcessTree(cmd)
		<-waitDone
		return ctx.Err()
	}

	return pagerResult(result.copyErr, waitErr, sourceClosed)
}

func pagerResult(copyErr, waitErr error, sourceClosed bool) error {
	if copyErr != nil && waitErr == nil && !core.IsBrokenPipe(copyErr) && !(sourceClosed && isClosedPagerInput(copyErr)) {
		return copyErr
	}
	if waitErr != nil && !isEarlyPagerExit(waitErr) {
		return fmt.Errorf("pager exited unsuccessfully: %w", waitErr)
	}
	return nil
}

type copyResult struct {
	copyErr error
}

func copyContext(ctx context.Context, src io.Reader, dst io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := src.(io.Closer); !ok {
		_, err := io.Copy(dst, src)
		return err
	}
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(dst, src)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		closeReader(src)
		return ctx.Err()
	}
}

func closeReader(src io.Reader) {
	if closer, ok := src.(io.Closer); ok {
		_ = closer.Close()
	}
}

func waitForCopy(done <-chan copyResult) copyResult {
	return <-done
}

func isEarlyPagerExit(err error) bool {
	return err == nil || pagerExitWasSIGPIPE(err)
}

func isClosedPagerInput(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrClosed) ||
		strings.Contains(strings.ToLower(err.Error()), "closed")
}

// Command describes a pager executable and its arguments.
type Command struct {
	Program string
	Args    []string
}

// CommandFromEnv parses PAGER without invoking a shell. It keeps the legacy
// fallback behavior for callers that only need to inspect the selected command;
// StreamContext uses commandFromLookup so malformed user input is reported.
func CommandFromEnv(getenv func(string) string) Command {
	command, err := commandFromLookup(func(name string) (string, bool) {
		if getenv == nil {
			return "", false
		}
		value := getenv(name)
		return value, value != ""
	})
	if err != nil {
		return defaultCommand(func(string) (string, bool) { return "", false })
	}
	return command
}

func commandFromLookup(lookup func(string) (string, bool)) (Command, error) {
	if value, ok := lookup("PAGER"); ok && value != "" {
		words, err := splitWords(value)
		if err != nil {
			return Command{}, fmt.Errorf("invalid PAGER: %w", err)
		}
		if len(words) == 0 {
			return Command{}, errors.New("invalid PAGER: command is empty")
		}
		return Command{Program: words[0], Args: words[1:]}, nil
	}
	return defaultCommand(lookup), nil
}

func defaultCommand(lookup func(string) (string, bool)) Command {
	command := Command{Program: "less"}
	if _, ok := lookup("LESS"); !ok {
		command.Args = []string{"-FIRX"}
	}
	return command
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
				// POSIX shells treat backslash as special for only these
				// characters inside double quotes. Preserve it for all others.
				if i+1 < len(input) {
					next := input[i+1]
					if next == '$' || next == '`' || next == '"' || next == '\\' || next == '\n' {
						escaped = true
						continue
					}
				}
				word.WriteByte(c)
				inWord = true
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
		case c < utf8.RuneSelf:
			if unicode.IsSpace(rune(c)) {
				flush()
				continue
			}
			word.WriteByte(c)
			inWord = true
		default:
			r, size := utf8.DecodeRuneInString(input[i:])
			if unicode.IsSpace(r) {
				flush()
				i += size - 1
				continue
			}
			word.WriteString(input[i : i+size])
			i += size - 1
			inWord = true
		}
	}
	if escaped || quote != 0 {
		return nil, errors.New("unterminated pager quoting")
	}
	flush()
	return words, nil
}
