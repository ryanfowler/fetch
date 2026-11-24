package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

// runUpdateWithExecutable runs update with an isolated cache directory and
// the given executable path. A release lookup fails the test: every case
// here ends in the preflight.
func runUpdateWithExecutable(t *testing.T, exe string, background bool) {
	t.Helper()
	cache := t.TempDir()
	t.Setenv("HOME", cache)
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("LOCALAPPDATA", cache)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the release lookup started, want a preflight failure")
	}))
	t.Cleanup(server.Close)
	t.Setenv("FETCH_INTERNAL_UPDATE_URL", server.URL)
	value := ""
	if background {
		value = "1"
	}
	t.Setenv("FETCH_INTERNAL_AUTO_UPDATE", value)
	previous := executablePath
	executablePath = func() (string, error) { return exe, nil }
	t.Cleanup(func() { executablePath = previous })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := update(ctx, core.TestPrinter(false), 0, true, false, NetworkConfig{})
	if err == nil || !strings.HasPrefix(err.Error(), "preflight:") {
		t.Fatalf("update() error = %v, want a preflight error", err)
	}
}

// updateIsDue reports whether an automatic update would start now.
func updateIsDue(t *testing.T) bool {
	t.Helper()
	due, err := ShouldAttemptUpdate(context.Background(), core.TestPrinter(false), 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return due
}

func TestAutomaticUpdateWaitsAfterPermanentPreflightFailure(t *testing.T) {
	// Without a record, every later request would start another updater.
	runUpdateWithExecutable(t, filepath.Join(t.TempDir(), "missing"), true)
	if updateIsDue(t) {
		t.Fatal("an automatic update is due right after a permanent preflight failure")
	}
}

func TestAutomaticUpdateRetriesAfterTransientPreflightFailure(t *testing.T) {
	// A file that cannot run fails the --version probe. That can be
	// transient, for example during a package manager upgrade.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "fetch")
	if err := os.WriteFile(exe, []byte("not an executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	runUpdateWithExecutable(t, exe, true)
	if !updateIsDue(t) {
		t.Fatal("a transient preflight failure delayed the next automatic update")
	}
}

func TestExplicitUpdateDoesNotRecordPreflightFailure(t *testing.T) {
	runUpdateWithExecutable(t, filepath.Join(t.TempDir(), "missing"), false)
	if !updateIsDue(t) {
		t.Fatal("an explicit update recorded a preflight failure")
	}
}
