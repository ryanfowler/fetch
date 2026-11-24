package fileutil

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLockFileExcludesASecondHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, err := LockFile(context.Background(), path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := LockFile(context.Background(), path, 100*time.Millisecond); err == nil {
		second.Unlock()
		first.Unlock()
		t.Fatal("a second holder took the lock")
	}
	first.Unlock()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("Unlock did not remove the lock file: %v", err)
	}
	again, err := LockFile(context.Background(), path, time.Second)
	if err != nil {
		t.Fatalf("lock after Unlock: %v", err)
	}
	again.Unlock()
	again.Unlock() // A second Unlock is safe.
}

func TestLockFileIgnoresALeftoverFile(t *testing.T) {
	// A file left by a process that exited, or by an earlier version that
	// used exclusive creates, does not block the lock.
	path := filepath.Join(t.TempDir(), "lock")
	if err := os.WriteFile(path, []byte("12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := LockFile(context.Background(), path, time.Second)
	if err != nil {
		t.Fatalf("LockFile() with a leftover file: %v", err)
	}
	lock.Unlock()
}

func TestLockFileHonorsContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	held, err := LockFile(context.Background(), path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LockFile(ctx, path, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("LockFile() error = %v, want context.Canceled", err)
	}
}

func TestLockFileHelperProcess(t *testing.T) {
	path := os.Getenv("FETCH_TEST_LOCK_PATH")
	if path == "" {
		return
	}
	if _, err := LockFile(context.Background(), path, time.Second); err != nil {
		fmt.Println("lock failed:", err)
		os.Exit(1)
	}
	fmt.Println("locked")
	for {
		time.Sleep(time.Hour)
	}
}

func TestLockFileIsReleasedWhenTheHolderDies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockFileHelperProcess$")
	cmd.Env = append(os.Environ(), "FETCH_TEST_LOCK_PATH="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "locked" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("helper did not take the lock: %q, %v", line, err)
	}
	if lock, err := LockFile(context.Background(), path, 100*time.Millisecond); err == nil {
		lock.Unlock()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("lock was taken while the helper held it")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	// The helper's file is still there, but its lock is gone.
	lock, err := LockFile(context.Background(), path, 2*time.Second)
	if err != nil {
		t.Fatalf("lock after the holder died: %v", err)
	}
	lock.Unlock()
}
