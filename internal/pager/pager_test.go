package pager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestCommandFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want Command
	}{
		{
			name: "default less flags",
			want: Command{Program: "less", Args: []string{"-FIRX"}},
		},
		{
			name: "LESS disables default flags",
			env:  map[string]string{"LESS": "-SR"},
			want: Command{Program: "less"},
		},
		{
			name: "quoted pager",
			env:  map[string]string{"PAGER": `"/tmp/my pager" --prompt='fetch > ' --pattern=a\ b`},
			want: Command{Program: "/tmp/my pager", Args: []string{"--prompt=fetch > ", "--pattern=a b"}},
		},
		{
			name: "invalid pager falls back",
			env:  map[string]string{"PAGER": `less "unterminated`},
			want: Command{Program: "less", Args: []string{"-FIRX"}},
		},
		{
			name: "shell operators are arguments",
			env:  map[string]string{"PAGER": "cat | unexpected"},
			want: Command{Program: "cat", Args: []string{"|", "unexpected"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := CommandFromEnv(func(name string) string { return test.env[name] })
			if got.Program != test.want.Program || !sameStrings(got.Args, test.want.Args) {
				t.Fatalf("CommandFromEnv() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestShouldPage(t *testing.T) {
	if !ShouldPage(core.PagerAuto, true, false) {
		t.Fatal("auto mode should page terminal output")
	}
	if ShouldPage(core.PagerAuto, false, false) {
		t.Fatal("auto mode should not page redirected output")
	}
	if ShouldPage(core.PagerAuto, true, true) {
		t.Fatal("images should bypass the pager")
	}
	if !ShouldPage(core.PagerOn, false, false) {
		t.Fatal("on mode should page redirected output")
	}
	if ShouldPage(core.PagerOff, true, false) {
		t.Fatal("off mode should not page")
	}
}

func TestStreamContextTerminatesPagerProcessGroup(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("starts a Unix subprocess")
	}

	fixtureDir := t.TempDir()
	readyPath := filepath.Join(fixtureDir, "ready")
	childPIDPath := filepath.Join(fixtureDir, "child.pid")
	pagerPath := filepath.Join(fixtureDir, "pager.sh")
	if err := os.WriteFile(pagerPath, []byte("#!/bin/sh\nsleep 30 &\nchild_pid=$!\nprintf '%s\\n' \"$child_pid\" > \"$FETCH_TEST_PAGER_CHILD_PID\"\nprintf ready > \"$FETCH_TEST_PAGER_READY\"\nwait \"$child_pid\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FETCH_TEST_PAGER_READY", readyPath)
	t.Setenv("FETCH_TEST_PAGER_CHILD_PID", childPIDPath)
	t.Setenv("PAGER", pagerPath)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan error, 1)
	go func() {
		done <- StreamContext(ctx, strings.NewReader("help"), core.PagerOn, false, false, io.Discard)
	}()
	childPID := 0
	streamDone := false
	t.Cleanup(func() {
		cancel()
		if !streamDone {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Log("pager cleanup exceeded its deadline")
			}
		}
		if childPID != 0 && !testProcessExited(childPID) {
			killTestProcess(childPID)
			if !waitForTestProcessExit(childPID, time.Second) {
				t.Logf("pager child process %d did not exit during cleanup", childPID)
			}
		}
	})

	readyDeadline := time.NewTimer(5 * time.Second)
	defer readyDeadline.Stop()
	readyTicker := time.NewTicker(5 * time.Millisecond)
	defer readyTicker.Stop()
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		select {
		case <-readyDeadline.C:
			t.Fatal("pager fixture did not start before the deadline")
		case <-ctx.Done():
			t.Fatal("pager fixture did not start before the deadline")
		case <-readyTicker.C:
		}
	}

	pidData, err := os.ReadFile(childPIDPath)
	if err != nil {
		t.Fatalf("read pager child PID: %v", err)
	}
	childPID, err = strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil || childPID <= 0 {
		t.Fatalf("invalid pager child PID %q", pidData)
	}
	if testProcessExited(childPID) {
		t.Fatalf("pager child process %d exited before cancellation", childPID)
	}

	cancel()
	select {
	case streamErr := <-done:
		streamDone = true
		if streamErr == nil {
			t.Fatal("canceled pager returned nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pager process group did not terminate")
	}
	if !waitForTestProcessExit(childPID, time.Second) {
		t.Fatalf("pager child process %d survived cancellation", childPID)
	}
}

func TestStreamContextReportsPagerStartFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a Unix-style missing executable path")
	}
	t.Setenv("PAGER", t.TempDir()+"/missing-pager")
	err := StreamContext(context.Background(), strings.NewReader("help\n"), core.PagerOn, false, false, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "unable to start pager") {
		t.Fatalf("missing pager error = %v", err)
	}
}

func TestStreamContextStopsSourceWhenPagerExits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh and head")
	}
	t.Setenv("PAGER", "sh -c 'head -c 1 >/dev/null'")
	source := newBlockingReader("long response")
	start := time.Now()
	if err := StreamContext(context.Background(), source, core.PagerOn, false, false, io.Discard); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("pager did not stop a blocked source: %s", elapsed)
	}
	if !source.wasClosed() {
		t.Fatal("pager exit did not close the source")
	}
}

func TestSplitWords(t *testing.T) {
	words, err := splitWords(`less --prompt='fetch > ' --pattern=a\ b`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"less", "--prompt=fetch > ", "--pattern=a b"}
	if !sameStrings(words, want) {
		t.Fatalf("splitWords() = %q, want %q", words, want)
	}
	if _, err := splitWords(`less "unterminated`); err == nil {
		t.Fatal("unterminated quote was accepted")
	}
}

type blockingReader struct {
	data   []byte
	closed chan struct{}
	once   chan struct{}
}

func newBlockingReader(data string) *blockingReader {
	return &blockingReader{data: []byte(data), closed: make(chan struct{}), once: make(chan struct{}, 1)}
}

func (r *blockingReader) Read(p []byte) (int, error) {
	select {
	case r.once <- struct{}{}:
		return copy(p, r.data), nil
	default:
		<-r.closed
		return 0, io.EOF
	}
}

func (r *blockingReader) Close() error {
	select {
	case <-r.closed:
	default:
		close(r.closed)
	}
	return nil
}

func (r *blockingReader) wasClosed() bool {
	select {
	case <-r.closed:
		return true
	default:
		return false
	}
}

func sameStrings(a, b []string) bool {
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

// startInteractiveTestPager runs StreamContext with an interactive pager
// helper process. The helper installs its SIGTERM handler before writing
// "ready", so SIGTERM is handled immediately without waiting on a shell sleep
// child process.
func startInteractiveTestPager(t *testing.T, mode string) (dir string, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("starts a Unix subprocess")
	}
	dir = t.TempDir()
	t.Setenv("FETCH_TEST_PAGER_DIR", dir)
	t.Setenv("FETCH_TEST_PAGER_INTERACTIVE_MODE", mode)
	t.Setenv("PAGER", fmt.Sprintf("%q -test.run=^TestPagerInteractiveHelper$", os.Args[0]))
	ctx, cancelFunc := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		// stdoutTerminal is true, so the pager stays in this process group,
		// as an interactive pager does.
		result <- StreamContext(ctx, strings.NewReader("data"), core.PagerOn, true, false, io.Discard)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			break
		}
		select {
		case err := <-result:
			cancelFunc()
			t.Fatalf("StreamContext returned before the pager started: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancelFunc()
			t.Fatal("pager fixture did not start before the deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return dir, cancelFunc, result
}

func TestPagerInteractiveHelper(t *testing.T) {
	mode := os.Getenv("FETCH_TEST_PAGER_INTERACTIVE_MODE")
	if mode == "" {
		return
	}
	dir := os.Getenv("FETCH_TEST_PAGER_DIR")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	if err := os.WriteFile(filepath.Join(dir, "ready"), []byte("ready"), 0o600); err != nil {
		os.Exit(1)
	}
	<-sigCh
	_ = os.WriteFile(filepath.Join(dir, "term"), []byte("term"), 0o600)
	if mode == "exit" {
		os.Exit(0)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestStreamContextLetsInteractivePagerHandleSIGTERM(t *testing.T) {
	dir, cancel, done := startInteractiveTestPager(t, "exit")
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("StreamContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("interactive pager did not exit")
	}
	if _, err := os.Stat(filepath.Join(dir, "term")); err != nil {
		t.Fatalf("pager did not receive SIGTERM before it exited: %v", err)
	}
}

func TestStreamContextKillsInteractivePagerThatIgnoresSIGTERM(t *testing.T) {
	previous := pagerExitGrace
	pagerExitGrace = 500 * time.Millisecond
	t.Cleanup(func() { pagerExitGrace = previous })

	// The helper records SIGTERM and keeps running until SIGKILL.
	dir, cancel, done := startInteractiveTestPager(t, "ignore")
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("StreamContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("interactive pager that ignores SIGTERM was not killed")
	}
	if elapsed := time.Since(start); elapsed < pagerExitGrace {
		t.Fatalf("pager was killed after %v, before the %v grace period", elapsed, pagerExitGrace)
	}
	if _, err := os.Stat(filepath.Join(dir, "term")); err != nil {
		t.Fatalf("pager did not receive SIGTERM before SIGKILL: %v", err)
	}
}

func TestStreamContextCancelsWhilePagerDoesNotReadInput(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("starts a Unix subprocess")
	}
	// The pager never reads, so a large non-closable input blocks the copy.
	t.Setenv("PAGER", "sleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := StreamContext(ctx, strings.NewReader(strings.Repeat("x", 4<<20)), core.PagerOn, false, false, io.Discard)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("StreamContext() error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("StreamContext() returned after %v", elapsed)
	}
}
