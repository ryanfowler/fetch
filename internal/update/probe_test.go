package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	probeHelperOnce sync.Once
	probeHelperDir  string
	probeHelperPath string
	probeHelperErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if probeHelperDir != "" {
		_ = os.RemoveAll(probeHelperDir)
	}
	os.Exit(code)
}

func TestGetExeVersionProbeBoundsAndValidatesOutput(t *testing.T) {
	helper := buildProbeHelper(t)

	t.Run("valid", func(t *testing.T) {
		t.Setenv("FETCH_PROBE_HELPER_MODE", "valid")
		got, err := getExeVersion(t.Context(), helper)
		if err != nil {
			t.Fatalf("getExeVersion: %v", err)
		}
		if got != "v1.2.3" {
			t.Fatalf("getExeVersion = %q, want v1.2.3", got)
		}
	})

	for _, test := range []struct {
		name string
		mode string
	}{
		{name: "empty", mode: "empty"},
		{name: "unrelated", mode: "unrelated"},
		{name: "missing version", mode: "missing-version"},
		{name: "extra output", mode: "extra-output"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("FETCH_PROBE_HELPER_MODE", test.mode)
			if _, err := getExeVersion(t.Context(), helper); err == nil {
				t.Fatal("getExeVersion unexpectedly accepted malformed output")
			}
		})
	}
}

func TestExecutableProbeBoundsStdoutAndStderr(t *testing.T) {
	helper := buildProbeHelper(t)
	for _, mode := range []string{"stdout-flood", "stderr-flood"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("FETCH_PROBE_HELPER_MODE", mode)
			_, err := getExeVersion(t.Context(), helper)
			if err == nil || !strings.Contains(err.Error(), "exceeded limit") {
				t.Fatalf("getExeVersion error = %v, want bounded-output error", err)
			}
		})
	}
}

func TestExecutableProbeClosesInheritedDescriptorsAndProcesses(t *testing.T) {
	previous := executableProbeTimeout
	executableProbeTimeout = 15 * time.Second
	t.Cleanup(func() { executableProbeTimeout = previous })

	helper := buildProbeHelper(t)
	marker := filepath.Join(t.TempDir(), "child-started")
	t.Setenv("FETCH_PROBE_HELPER_MODE", "inherit")
	t.Setenv("FETCH_PROBE_HELPER_MARKER", marker)

	started := time.Now()
	got, err := getExeVersion(t.Context(), helper)
	if err != nil {
		t.Fatalf("getExeVersion: %v", err)
	}
	if got != "v1.2.3" {
		t.Fatalf("getExeVersion = %q, want v1.2.3", got)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("probe with inherited descriptors took %s", elapsed)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("child marker: %v", err)
	}
}

func TestExecutableProbeHonorsParentDeadline(t *testing.T) {
	previous := executableProbeTimeout
	executableProbeTimeout = 15 * time.Second
	t.Cleanup(func() { executableProbeTimeout = previous })

	helper := buildProbeHelper(t)
	t.Setenv("FETCH_PROBE_HELPER_MODE", "hang")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := getExeVersion(ctx, helper)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("getExeVersion error = %v, want timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("probe did not honor parent deadline: %s", elapsed)
	}
}

func TestExecutableProbeHasLocalDeadline(t *testing.T) {
	previous := executableProbeTimeout
	executableProbeTimeout = 500 * time.Millisecond
	t.Cleanup(func() { executableProbeTimeout = previous })

	helper := buildProbeHelper(t)
	t.Setenv("FETCH_PROBE_HELPER_MODE", "hang")

	started := time.Now()
	_, err := getExeVersion(context.Background(), helper)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("getExeVersion error = %v, want local timeout", err)
	}
	if elapsed := time.Since(started); elapsed > executableProbeTimeout+10*time.Second {
		t.Fatalf("local probe deadline exceeded: %s", elapsed)
	}
}

func TestValidateStagedExecutableSharesProbe(t *testing.T) {
	helper := buildProbeHelper(t)
	t.Setenv("FETCH_PROBE_HELPER_MODE", "valid")
	if err := validateStagedExecutable(t.Context(), helper); err != nil {
		t.Fatalf("validateStagedExecutable: %v", err)
	}
}

func buildProbeHelper(t *testing.T) string {
	t.Helper()
	probeHelperOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fetch-probe-helper-*")
		if err != nil {
			probeHelperErr = fmt.Errorf("create temp dir: %w", err)
			return
		}
		probeHelperDir = dir
		source := filepath.Join(dir, "main.go")
		if err := os.WriteFile(source, []byte(probeHelperSource), 0600); err != nil {
			probeHelperErr = fmt.Errorf("write probe helper: %w", err)
			return
		}
		helper := filepath.Join(dir, "probe-helper")
		if os.PathSeparator == '\\' {
			helper += ".exe"
		}
		goTool, err := exec.LookPath("go")
		if err != nil {
			probeHelperErr = fmt.Errorf("find go tool: %w", err)
			return
		}
		cmd := exec.Command(goTool, "build", "-o", helper, "main.go")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GO111MODULE=off")
		if output, err := cmd.CombinedOutput(); err != nil {
			probeHelperErr = fmt.Errorf("build probe helper: %w\n%s", err, output)
			return
		}
		probeHelperPath = helper
	})
	if probeHelperErr != nil {
		t.Fatal(probeHelperErr)
	}
	return probeHelperPath
}

const probeHelperSource = `package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	switch os.Getenv("FETCH_PROBE_HELPER_MODE") {
	case "valid":
		fmt.Println("fetch v1.2.3")
	case "empty":
	case "unrelated":
		fmt.Println("not-fetch v1.2.3")
	case "missing-version":
		fmt.Println("fetch")
	case "extra-output":
		fmt.Println("fetch v1.2.3 unrelated")
	case "stdout-flood":
		_, _ = os.Stdout.Write([]byte(strings.Repeat("x", 1<<20)))
	case "stderr-flood":
		fmt.Fprintln(os.Stdout, "fetch v1.2.3")
		_, _ = os.Stderr.Write([]byte(strings.Repeat("x", 1<<20)))
	case "inherit":
		child := exec.Command(os.Args[0], "--version")
		child.Env = append(os.Environ(), "FETCH_PROBE_HELPER_MODE=child")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if marker := os.Getenv("FETCH_PROBE_HELPER_MARKER"); marker != "" {
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(marker); err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		fmt.Println("fetch v1.2.3")
	case "child":
		marker := os.Getenv("FETCH_PROBE_HELPER_MARKER")
		if marker != "" {
			_ = os.WriteFile(marker, []byte("started"), 0600)
		}
		for {
			time.Sleep(time.Hour)
		}
	case "hang":
		for {
			time.Sleep(time.Hour)
		}
	}
}
`
