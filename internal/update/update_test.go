package update

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsVersionTag(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"v1.2.3", true},
		{"v0.0.0", true},
		{"v10.20.30", true},
		{"v100.200.300", true},
		{"v(dev)", false},
		{"v0.0.0-20231215164305-abcdef123456", false},
		{"1.2.3", false},
		{"v1.2", false},
		{"v1.2.3.4", false},
		{"v.1.2", false},
		{"v1..2", false},
		{"v1.2.", false},
		{"", false},
		{"v", false},
		{"vx.y.z", false},
		{"v1.2.3-rc1", false},
		{"v1.2.3+meta", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isVersionTag(tt.input); got != tt.want {
				t.Errorf("isVersionTag(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBoundUpdateErrorRedactsURLAndQuery(t *testing.T) {
	err := &url.Error{
		Op:  "Get",
		URL: "https://update-user:update-password@example.test/releases/latest?access_token=update-query-secret&safe=ok",
		Err: errors.New("connection refused"),
	}
	got := boundUpdateError(err)
	for _, secret := range []string{"update-user", "update-password", "update-query-secret"} {
		if strings.Contains(got.Error(), secret) {
			t.Fatalf("bounded update error leaked %q: %q", secret, got)
		}
	}
	want := "https://example.test/releases/latest?access_token=%5BREDACTED%5D&safe=ok"
	if !strings.Contains(got.Error(), want) {
		t.Fatalf("bounded update error = %q, want redacted URL %q", got, want)
	}
}

func TestUpdateLastAttemptTime_OverwritesExistingMetadata(t *testing.T) {
	dir := t.TempDir()

	first := time.Unix(100, 0)
	if err := updateLastAttemptTime(dir, first); err != nil {
		t.Fatalf("first updateLastAttemptTime failed: %v", err)
	}

	second := time.Unix(200, 0)
	if err := updateLastAttemptTime(dir, second); err != nil {
		t.Fatalf("second updateLastAttemptTime failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		t.Fatalf("reading metadata file: %v", err)
	}
	if string(data) != `{"schema_version":1,"last_attempt_at":"1970-01-01T00:03:20Z"}` {
		t.Fatalf("metadata.json = %q", data)
	}
}

func TestShouldAttemptUpdateTreatsMetadataDefensively(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("HOME", cache)
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("LOCALAPPDATA", cache)
	cacheDir, err := getCacheDir()
	if err != nil {
		t.Fatal(err)
	}

	write := func(t *testing.T, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(cacheDir, "metadata.json"), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}

	for _, test := range []struct {
		name string
		data string
	}{
		{name: "missing", data: ""},
		{name: "malformed", data: "{"},
		{name: "wrong schema", data: `{"schema_version":99,"last_attempt_at":"2020-01-01T00:00:00Z"}`},
		{name: "zero time", data: `{"schema_version":1,"last_attempt_at":"0001-01-01T00:00:00Z"}`},
		{name: "future time", data: `{"schema_version":1,"last_attempt_at":"2999-01-01T00:00:00Z"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name != "missing" {
				write(t, test.data)
			}
			due, err := ShouldAttemptUpdate(t.Context(), nil, 24*time.Hour)
			if err != nil {
				t.Fatalf("ShouldAttemptUpdate: %v", err)
			}
			if !due {
				t.Fatal("invalid metadata suppressed an update check")
			}
			if test.name == "missing" {
				return
			}
			_ = os.Remove(filepath.Join(cacheDir, "metadata.json"))
		})
	}
}

func TestShouldAttemptUpdateHonorsIntervalAndDisabling(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("HOME", cache)
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("LOCALAPPDATA", cache)
	dir, err := getCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := updateLastAttemptTime(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if due, err := ShouldAttemptUpdate(t.Context(), nil, time.Hour); err != nil || due {
		t.Fatalf("recent metadata due=%v err=%v", due, err)
	}
	if due, err := ShouldAttemptUpdate(t.Context(), nil, -time.Hour); err != nil || due {
		t.Fatalf("disabled interval due=%v err=%v", due, err)
	}
}

func TestShouldAttemptUpdateRejectsSymlinkedMetadata(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("HOME", cache)
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("LOCALAPPDATA", cache)
	dir, err := getCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "metadata")
	if err := os.WriteFile(target, []byte(`{"schema_version":1,"last_attempt_at":"2999-01-01T00:00:00Z"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "metadata.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	due, err := ShouldAttemptUpdate(t.Context(), nil, time.Hour)
	if err != nil {
		t.Fatalf("ShouldAttemptUpdate: %v", err)
	}
	if !due {
		t.Fatal("symlinked metadata suppressed an update check")
	}
}
