package update

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("probe with inherited descriptors took %s", elapsed)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("child marker: %v", err)
	}
}

func TestExecutableProbeHonorsParentDeadline(t *testing.T) {
	helper := buildProbeHelper(t)
	t.Setenv("FETCH_PROBE_HELPER_MODE", "hang")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := getExeVersion(ctx, helper)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("getExeVersion error = %v, want timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("probe did not honor parent deadline: %s", elapsed)
	}
}

func TestExecutableProbeHasLocalDeadline(t *testing.T) {
	helper := buildProbeHelper(t)
	t.Setenv("FETCH_PROBE_HELPER_MODE", "hang")

	started := time.Now()
	_, err := getExeVersion(context.Background(), helper)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("getExeVersion error = %v, want local timeout", err)
	}
	if elapsed := time.Since(started); elapsed > executableProbeTimeout+2*time.Second {
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
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	if err := os.WriteFile(source, []byte(probeHelperSource), 0600); err != nil {
		t.Fatalf("write probe helper: %v", err)
	}
	helper := filepath.Join(dir, "probe-helper")
	if os.PathSeparator == '\\' {
		helper += ".exe"
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("find go tool: %v", err)
	}
	cmd := exec.Command(goTool, "build", "-o", helper, "main.go")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GO111MODULE=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build probe helper: %v\n%s", err, output)
	}
	return helper
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
