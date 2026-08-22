package skill

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testBundle(t *testing.T) Bundle {
	t.Helper()
	bundle, err := NewBundle("vtest", []File{
		{Path: "SKILL.md", Data: []byte("# fetch\n")},
		{Path: "references/http.md", Data: []byte("http\n")},
		{Path: "evals/evals.json", Data: []byte(`{"evals":[]}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func runAction(t *testing.T, options Options, bundle Bundle) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	options.Stdout = &stdout
	options.Stderr = &stderr
	status, err := Execute(context.Background(), options, bundle)
	if err != nil {
		t.Fatalf("Execute() error = %v\nstderr=%s", err, stderr.String())
	}
	return status, stdout.String(), stderr.String()
}

func TestPrintIsExactlyTheEmbeddedSkill(t *testing.T) {
	bundle := testBundle(t)
	_, stdout, _ := runAction(t, Options{Print: true}, bundle)
	if stdout != "# fetch\n" {
		t.Fatalf("printed skill = %q", stdout)
	}
}

func TestInstallManifestAndUninstall(t *testing.T) {
	bundle := testBundle(t)
	root := t.TempDir()
	status, _, stderr := runAction(t, Options{InstallAgent: "agents", Scope: "project", ProjectDir: root}, bundle)
	if status != 0 || !strings.Contains(stderr, "Installed fetch skill") {
		t.Fatalf("install status=%d stderr=%q", status, stderr)
	}
	path := filepath.Join(root, ".agents", "skills", "fetch")
	metadataBytes, err := os.ReadFile(filepath.Join(path, metadataName))
	if err != nil {
		t.Fatal(err)
	}
	var metadata installationMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.FetchVersion != "vtest" || metadata.Files["SKILL.md"].Size != len("# fetch\n") {
		t.Fatalf("metadata = %+v", metadata)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == metadataName {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" {
			continue
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0700 {
				t.Fatalf("%s mode = %o, want 700", entry.Name(), info.Mode().Perm())
			}
			continue
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o, want 600", entry.Name(), info.Mode().Perm())
		}
	}

	status, _, _ = runAction(t, Options{UninstallAgent: "agents", Scope: "project", ProjectDir: root}, bundle)
	if status != 0 {
		t.Fatalf("uninstall status = %d", status)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("skill directory still exists, stat error = %v", err)
	}
}

func TestModifiedInstallationRequiresForce(t *testing.T) {
	bundle := testBundle(t)
	root := t.TempDir()
	runAction(t, Options{InstallAgent: "agents", Scope: "project", ProjectDir: root}, bundle)
	path := filepath.Join(root, ".agents", "skills", "fetch")
	if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("changed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	status, err := Execute(context.Background(), Options{
		InstallAgent: "agents", Scope: "project", ProjectDir: root,
		Stdout: &bytes.Buffer{}, Stderr: &stderr,
	}, bundle)
	if err == nil || status == 0 || !strings.Contains(err.Error(), "use --force") {
		t.Fatalf("modified install status=%d err=%v stderr=%q", status, err, stderr.String())
	}
	if _, err := os.ReadFile(filepath.Join(path, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	_, _, forcedStderr := runAction(t, Options{InstallAgent: "agents", Scope: "project", ProjectDir: root, Force: true}, bundle)
	if !strings.Contains(forcedStderr, "Installed") {
		t.Fatalf("forced install output = %q", forcedStderr)
	}
}

func TestForgedEmptyManifestIsNotManaged(t *testing.T) {
	bundle := testBundle(t)
	root := t.TempDir()
	path := filepath.Join(root, ".agents", "skills", "fetch")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(installationMetadata{SkillVersion: SkillVersion, Files: map[string]fileRecord{}})
	if err := os.WriteFile(filepath.Join(path, metadataName), data, 0600); err != nil {
		t.Fatal(err)
	}
	status, err := Execute(context.Background(), Options{
		UninstallAgent: "agents", Scope: "project", ProjectDir: root,
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	}, bundle)
	if err == nil || status == 0 || !strings.Contains(err.Error(), "modified") {
		t.Fatalf("forged uninstall status=%d err=%v", status, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestSymlinkedDestinationComponentIsRejected(t *testing.T) {
	bundle := testBundle(t)
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".agents")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	var stderr bytes.Buffer
	status, err := Execute(context.Background(), Options{
		InstallAgent: "agents", Scope: "project", ProjectDir: root,
		Stdout: &bytes.Buffer{}, Stderr: &stderr,
	}, bundle)
	if err == nil || status == 0 || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink install status=%d err=%v", status, err)
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatalf("symlink target was modified: %v", entries)
	}
}

func TestDryRunDoesNotCreateLockOrDirectories(t *testing.T) {
	bundle := testBundle(t)
	root := t.TempDir()
	status, _, stderr := runAction(t, Options{InstallAgent: "all", Scope: "project", ProjectDir: root, DryRun: true}, bundle)
	if status != 0 || !strings.Contains(stderr, "no files were written") {
		t.Fatalf("dry-run status=%d stderr=%q", status, stderr)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("dry-run created entries: %v", entries)
	}
}
