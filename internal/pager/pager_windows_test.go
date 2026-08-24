//go:build windows

package pager

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestStreamContextTerminatesPagerJobTree(t *testing.T) {
	fixtureDir := t.TempDir()
	readyPath := filepath.Join(fixtureDir, "ready")
	childPIDPath := filepath.Join(fixtureDir, "child.pid")
	t.Setenv("FETCH_TEST_PAGER_WINDOWS_MODE", "wrapper")
	t.Setenv("FETCH_TEST_PAGER_WINDOWS_READY", readyPath)
	t.Setenv("FETCH_TEST_PAGER_WINDOWS_CHILD_PID", childPIDPath)
	t.Setenv("PAGER", fmt.Sprintf("%q -test.run=^TestPagerWindowsWrapper$", os.Args[0]))

	ctx, cancel := context.WithCancel(context.Background())
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
			case <-time.After(2 * time.Second):
				t.Log("pager cleanup exceeded its deadline")
			}
		}
		if childPID != 0 && !waitForTestProcessExit(childPID, time.Second) {
			killTestProcess(childPID)
		}
	})

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("Windows pager wrapper did not start before the deadline")
		case <-done:
			t.Fatal("Windows pager exited before creating its descendant")
		case <-time.After(10 * time.Millisecond):
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
		t.Fatal("canceled pager job did not terminate")
	}
	if !waitForTestProcessExit(childPID, 2*time.Second) {
		t.Fatalf("pager child process %d survived cancellation", childPID)
	}
}

func TestPagerWindowsWrapper(t *testing.T) {
	if os.Getenv("FETCH_TEST_PAGER_WINDOWS_MODE") != "wrapper" {
		return
	}
	child := exec.Command(os.Args[0], "-test.run=^TestPagerWindowsChild$")
	child.Env = append(os.Environ(), "FETCH_TEST_PAGER_WINDOWS_MODE=child")
	if err := child.Start(); err != nil {
		t.Fatalf("start pager descendant: %v", err)
	}
	if err := os.WriteFile(os.Getenv("FETCH_TEST_PAGER_WINDOWS_CHILD_PID"), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		_ = child.Process.Kill()
		t.Fatalf("write pager child PID: %v", err)
	}
	if err := os.WriteFile(os.Getenv("FETCH_TEST_PAGER_WINDOWS_READY"), []byte("ready\n"), 0o600); err != nil {
		_ = child.Process.Kill()
		t.Fatalf("write pager ready marker: %v", err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("pager descendant exited: %v", err)
	}
}

func TestPagerWindowsChild(t *testing.T) {
	if os.Getenv("FETCH_TEST_PAGER_WINDOWS_MODE") != "child" {
		return
	}
	for {
		time.Sleep(time.Hour)
	}
}
