package fetch

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestClipboardCopierFinishCopiesEmptyBuffer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clipboard")
	t.Setenv("FETCH_TEST_CLIPBOARD_HELPER", "1")
	t.Setenv("FETCH_TEST_CLIPBOARD_OUT", path)

	cc := &clipboardCopier{
		cmd: &clipboardCmd{
			path: os.Args[0],
			args: []string{"-test.run=^TestClipboardCommandHelper$"},
		},
		buf: &limitedBuffer{max: maxBodyBytes},
	}

	cc.finish(context.Background(), newTestPrinter())

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("clipboard command was not invoked: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("copied %d bytes, want empty clipboard data", len(data))
	}
}

func TestClipboardCommandHelper(t *testing.T) {
	if os.Getenv("FETCH_TEST_CLIPBOARD_HELPER") != "1" {
		return
	}
	if os.Getenv("FETCH_TEST_CLIPBOARD_DESCENDANT") == "1" {
		// Keep the descendant alive without triggering the Go runtime's
		// deadlock detector on platforms where it exits a blocked test
		// process with status 2.
		for {
			time.Sleep(time.Hour)
		}
	}
	if os.Getenv("FETCH_TEST_CLIPBOARD_HOLDER") == "1" {
		// A background clipboard holder, as xclip forks: it publishes the
		// data after its parent has exited.
		time.Sleep(200 * time.Millisecond)
		out := os.Getenv("FETCH_TEST_CLIPBOARD_OUT")
		if err := os.Rename(out+".pending", out); err != nil {
			fmt.Fprintf(os.Stderr, "clipboard holder: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getenv("FETCH_TEST_CLIPBOARD_BACKGROUND") == "1" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			t.Fatalf("unable to read stdin: %v", err)
		}
		if err := os.WriteFile(os.Getenv("FETCH_TEST_CLIPBOARD_OUT")+".pending", data, 0o600); err != nil {
			t.Fatalf("unable to write pending clipboard output: %v", err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestClipboardCommandHelper$")
		cmd.Env = append(os.Environ(), "FETCH_TEST_CLIPBOARD_HOLDER=1")
		if err := cmd.Start(); err != nil {
			t.Fatalf("unable to start clipboard holder: %v", err)
		}
		if os.Getenv("FETCH_TEST_CLIPBOARD_FAIL") == "1" {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getenv("FETCH_TEST_CLIPBOARD_FORK") == "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestClipboardCommandHelper$")
		cmd.Env = append(os.Environ(), "FETCH_TEST_CLIPBOARD_DESCENDANT=1")
		cmd.Stdin = os.Stdin
		if err := cmd.Start(); err != nil {
			t.Fatalf("unable to start clipboard descendant: %v", err)
		}
	}
	if os.Getenv("FETCH_TEST_CLIPBOARD_BLOCK") == "1" {
		for {
			time.Sleep(time.Hour)
		}
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		t.Fatalf("unable to read stdin: %v", err)
	}
	if err := os.WriteFile(os.Getenv("FETCH_TEST_CLIPBOARD_OUT"), data, 0o600); err != nil {
		t.Fatalf("unable to write clipboard output: %v", err)
	}
	os.Exit(0)
}

func TestCopyToClipboardTimeout(t *testing.T) {
	// Keep both processes alive so the test does not depend on the platform's
	// stdin pipe capacity.
	t.Setenv("FETCH_TEST_CLIPBOARD_HELPER", "1")
	t.Setenv("FETCH_TEST_CLIPBOARD_FORK", "1")
	t.Setenv("FETCH_TEST_CLIPBOARD_BLOCK", "1")

	start := time.Now()
	err := copyToClipboardWithTimeout(context.Background(), &clipboardCmd{
		path: os.Args[0],
		args: []string{"-test.run=^TestClipboardCommandHelper$"},
	}, bytes.Repeat([]byte("x"), 256<<10), 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "clipboard command timed out") {
		t.Fatalf("copyToClipboardWithTimeout() error = %v, want timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("copyToClipboardWithTimeout() took %s, want bounded return", elapsed)
	}
}

func TestCopyToClipboardKeepsBackgroundHolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows clipboard commands do not fork a holder")
	}
	out := filepath.Join(t.TempDir(), "clipboard")
	t.Setenv("FETCH_TEST_CLIPBOARD_HELPER", "1")
	t.Setenv("FETCH_TEST_CLIPBOARD_BACKGROUND", "1")
	t.Setenv("FETCH_TEST_CLIPBOARD_OUT", out)

	err := copyToClipboardWithTimeout(context.Background(), &clipboardCmd{
		path: os.Args[0],
		args: []string{"-test.run=^TestClipboardCommandHelper$"},
	}, []byte("copied"), 5*time.Second)
	if err != nil {
		t.Fatalf("copyToClipboardWithTimeout() error = %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(out)
		if err == nil {
			if string(data) != "copied" {
				t.Fatalf("clipboard data = %q, want %q", data, "copied")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("clipboard data was not published within 5s; the background holder was stopped or failed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCopyToClipboardStopsHolderOfFailedCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows clipboard commands do not fork a holder")
	}
	out := filepath.Join(t.TempDir(), "clipboard")
	t.Setenv("FETCH_TEST_CLIPBOARD_HELPER", "1")
	t.Setenv("FETCH_TEST_CLIPBOARD_BACKGROUND", "1")
	t.Setenv("FETCH_TEST_CLIPBOARD_FAIL", "1")
	t.Setenv("FETCH_TEST_CLIPBOARD_OUT", out)

	err := copyToClipboardWithTimeout(context.Background(), &clipboardCmd{
		path: os.Args[0],
		args: []string{"-test.run=^TestClipboardCommandHelper$"},
	}, []byte("copied"), 5*time.Second)
	if err == nil {
		t.Fatal("copyToClipboardWithTimeout() succeeded for a failed command")
	}
	// The holder publishes 200ms after it starts unless it was stopped.
	time.Sleep(time.Second)
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("holder of a failed command was not stopped: %v", err)
	}
}

func TestStreamToStdoutDrainsSuppressedBinaryForClipboard(t *testing.T) {
	wasStdoutTerm := core.IsStdoutTerm
	core.IsStdoutTerm = true
	t.Cleanup(func() {
		core.IsStdoutTerm = wasStdoutTerm
	})

	data := bytes.Repeat([]byte("a"), 4096)
	data[10] = 0

	lb := &limitedBuffer{max: int64(len(data))}
	r := io.TeeReader(bytes.NewReader(data), lb)
	if err := streamToStdout(r, newTestPrinter(), false, true, true); err != nil {
		t.Fatalf("streamToStdout returned error: %v", err)
	}

	if got := lb.buf.Bytes(); !bytes.Equal(got, data) {
		t.Fatalf("captured %d bytes, want %d", len(got), len(data))
	}
	if lb.overflow {
		t.Fatal("buffer should not overflow when response fits")
	}
}

func TestLimitedBuffer(t *testing.T) {
	t.Run("under limit", func(t *testing.T) {
		lb := &limitedBuffer{max: 10}
		n, err := lb.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 5 {
			t.Fatalf("expected n=5, got %d", n)
		}
		if lb.overflow {
			t.Fatal("overflow should be false")
		}
		if lb.buf.String() != "hello" {
			t.Fatalf("expected %q, got %q", "hello", lb.buf.String())
		}
	})

	t.Run("at limit", func(t *testing.T) {
		lb := &limitedBuffer{max: 5}
		n, err := lb.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 5 {
			t.Fatalf("expected n=5, got %d", n)
		}
		if lb.overflow {
			t.Fatal("overflow should be false at exact limit")
		}
		if lb.buf.String() != "hello" {
			t.Fatalf("expected %q, got %q", "hello", lb.buf.String())
		}
	})

	t.Run("over limit single write", func(t *testing.T) {
		lb := &limitedBuffer{max: 3}
		n, err := lb.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 5 {
			t.Fatalf("expected n=5, got %d", n)
		}
		if !lb.overflow {
			t.Fatal("overflow should be true")
		}
		if lb.buf.String() != "hel" {
			t.Fatalf("expected %q, got %q", "hel", lb.buf.String())
		}
	})

	t.Run("multiple writes crossing limit", func(t *testing.T) {
		lb := &limitedBuffer{max: 7}

		n, err := lb.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 5 {
			t.Fatalf("expected n=5, got %d", n)
		}
		if lb.overflow {
			t.Fatal("overflow should be false after first write")
		}

		n, err = lb.Write([]byte("world"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 5 {
			t.Fatalf("expected n=5, got %d", n)
		}
		if !lb.overflow {
			t.Fatal("overflow should be true after second write")
		}
		if lb.buf.String() != "hellowo" {
			t.Fatalf("expected %q, got %q", "hellowo", lb.buf.String())
		}
	})

	t.Run("writes after overflow are discarded", func(t *testing.T) {
		lb := &limitedBuffer{max: 3}
		lb.Write([]byte("hello"))
		if !lb.overflow {
			t.Fatal("overflow should be true")
		}

		n, err := lb.Write([]byte("more"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 4 {
			t.Fatalf("expected n=4, got %d", n)
		}
		if lb.buf.String() != "hel" {
			t.Fatalf("expected %q, got %q", "hel", lb.buf.String())
		}
	})

	t.Run("zero max", func(t *testing.T) {
		lb := &limitedBuffer{max: 0}
		n, err := lb.Write([]byte("a"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 1 {
			t.Fatalf("expected n=1, got %d", n)
		}
		if !lb.overflow {
			t.Fatal("overflow should be true")
		}
		if lb.buf.Len() != 0 {
			t.Fatalf("expected empty buffer, got %d bytes", lb.buf.Len())
		}
	})

	t.Run("tee reader not affected by overflow", func(t *testing.T) {
		lb := &limitedBuffer{max: 5}
		data := "hello world, this is a longer string"
		r := io.TeeReader(strings.NewReader(data), lb)

		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != data {
			t.Fatalf("TeeReader should return all data; got %q", got)
		}
		if !lb.overflow {
			t.Fatal("overflow should be true")
		}
		if lb.buf.String() != "hello" {
			t.Fatalf("expected %q in buffer, got %q", "hello", lb.buf.String())
		}
	})
}
