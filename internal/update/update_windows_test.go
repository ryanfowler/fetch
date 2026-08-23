//go:build windows

package update

import (
	"archive/zip"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestUnpackArtifact_PathTraversal(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			name:     "normal file",
			filename: "fetch.exe",
			wantErr:  false,
		},
		{
			name:     "path traversal with ..",
			filename: "../escape.txt",
			wantErr:  true,
		},
		{
			name:     "deep path traversal",
			filename: "../../Windows/System32/malicious.dll",
			wantErr:  true,
		},
		{
			name:     "absolute path",
			filename: "C:/Windows/System32/malicious.dll",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a zip archive with the test filename.
			archive := createZip(t, tt.filename, []byte("content"))

			// Create a temp directory for extraction.
			dir := t.TempDir()

			err := unpackArtifact(dir, bytes.NewReader(archive))
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for filename %q, got nil", tt.filename)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				// Verify file was created in the correct location.
				if _, err := os.Stat(filepath.Join(dir, tt.filename)); err != nil {
					t.Errorf("expected file to exist: %v", err)
				}
			}
		})
	}
}

func TestUnpackArtifact_RejectsNestedDirectoryEntry(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if _, err := zw.Create("bin/"); err != nil {
		t.Fatal(err)
	}
	fw, err := zw.Create("bin/fetch.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("content")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := unpackArtifact(dir, bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("unpackArtifact accepted a nested executable")
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "fetch.exe")); !os.IsNotExist(err) {
		t.Fatalf("nested payload exists after rejection, stat error = %v", err)
	}
}

func TestReconcileReplacementJournalInstallsStagedExecutable(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fetch.exe")
	staged := filepath.Join(dir, ".fetch.abcdefghijklmnop"+tempSuffix)
	relocated := filepath.Join(dir, ".fetch.ponmlkjihgfedcba"+relocatedSuffix)
	if err := os.WriteFile(staged, []byte("new executable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(relocated, []byte("old executable"), 0600); err != nil {
		t.Fatal(err)
	}
	journalPath := target + replacementJournalSuffix
	if err := writeReplacementJournal(journalPath, replacementJournal{
		Staged: filepath.Base(staged), Relocated: filepath.Base(relocated), OwnerPID: ^uint32(0),
	}); err != nil {
		t.Fatal(err)
	}

	if err := reconcileReplacementJournal(journalPath, target); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new executable" {
		t.Fatalf("target = %q, want staged executable", got)
	}
	for _, path := range []string{staged, relocated, journalPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("recovery artifact %q remains, stat error = %v", path, err)
		}
	}
}

func TestReconcileReplacementJournalRestoresRelocatedExecutable(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fetch.exe")
	relocated := filepath.Join(dir, ".fetch.abcdefghijklmnop"+relocatedSuffix)
	if err := os.WriteFile(relocated, []byte("old executable"), 0600); err != nil {
		t.Fatal(err)
	}
	journalPath := target + replacementJournalSuffix
	if err := writeReplacementJournal(journalPath, replacementJournal{
		Staged: ".fetch.ponmlkjihgfedcba" + tempSuffix, Relocated: filepath.Base(relocated), OwnerPID: ^uint32(0),
	}); err != nil {
		t.Fatal(err)
	}

	if err := reconcileReplacementJournal(journalPath, relocated); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old executable" {
		t.Fatalf("target = %q, want relocated executable", got)
	}
}

func TestReplacementRecoveryChildInheritsParentHandle(t *testing.T) {
	if os.Getenv("FETCH_TEST_REPLACEMENT_RECOVERY_COORDINATOR") == "1" {
		exePath, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		journalPath := os.Getenv("FETCH_TEST_REPLACEMENT_JOURNAL")
		journal, err := readReplacementJournal(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		journal.OwnerPID = uint32(os.Getpid())
		if err := os.Remove(journalPath); err != nil {
			t.Fatal(err)
		}
		if err := writeReplacementJournal(journalPath, journal); err != nil {
			t.Fatal(err)
		}
		if err := scheduleReplacementRecoveryOnShutdown(exePath, journalPath); err != nil {
			t.Fatal(err)
		}
		return
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "fetch.exe")
	staged := filepath.Join(dir, ".fetch.abcdefghijklmnop"+tempSuffix)
	relocated := filepath.Join(dir, ".fetch.ponmlkjihgfedcba"+relocatedSuffix)
	if err := copyFile(staged, os.Args[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(relocated, []byte("old executable"), 0600); err != nil {
		t.Fatal(err)
	}
	journalPath := target + replacementJournalSuffix
	if err := writeReplacementJournal(journalPath, replacementJournal{
		Staged: filepath.Base(staged), Relocated: filepath.Base(relocated), OwnerPID: ^uint32(0),
	}); err != nil {
		t.Fatal(err)
	}

	helperPattern := filepath.Join(filepath.Dir(os.Args[0]), ".fetch.*"+selfDeleteSuffix)
	beforeHelpers, err := filepath.Glob(helperPattern)
	if err != nil {
		t.Fatal(err)
	}
	before := make(map[string]bool, len(beforeHelpers))
	for _, path := range beforeHelpers {
		before[path] = true
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestReplacementRecoveryChildInheritsParentHandle$")
	cmd.Env = append(os.Environ(),
		"FETCH_TEST_REPLACEMENT_RECOVERY_COORDINATOR=1",
		"FETCH_TEST_REPLACEMENT_JOURNAL="+journalPath,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("recovery coordinator failed: %v\n%s", err, output)
	}

	deadline := time.Now().Add(15 * time.Second)
	for {
		info, err := os.Stat(target)
		if err == nil && info.Size() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery child did not install staged executable: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Lstat(journalPath); !os.IsNotExist(err) {
		t.Fatalf("replacement journal remains, stat error = %v", err)
	}
	for {
		helpers, err := filepath.Glob(helperPattern)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, path := range helpers {
			if !before[path] {
				found = true
				break
			}
		}
		if !found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("self-delete recovery helper was not removed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestReconcileReplacementJournalWaitsForActiveUpdater(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fetch.exe")
	staged := filepath.Join(dir, ".fetch.abcdefghijklmnop"+tempSuffix)
	relocated := filepath.Join(dir, ".fetch.ponmlkjihgfedcba"+relocatedSuffix)
	for path, content := range map[string]string{target: "current executable", staged: "new executable"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	journalPath := target + replacementJournalSuffix
	if err := writeReplacementJournal(journalPath, replacementJournal{
		Staged: filepath.Base(staged), Relocated: filepath.Base(relocated), OwnerPID: uint32(os.Getpid()),
	}); err != nil {
		t.Fatal(err)
	}
	if err := reconcileReplacementJournal(journalPath, target); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{target, staged, journalPath} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("active update artifact %q was removed: %v", path, err)
		}
	}
}

func TestReconcileReplacementJournalRemovesTruncatedPrecommitJournal(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fetch.exe")
	if err := os.WriteFile(target, []byte("current executable"), 0600); err != nil {
		t.Fatal(err)
	}
	journalPath := target + replacementJournalSuffix
	if err := os.WriteFile(journalPath, []byte(`{"staged":`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := reconcileReplacementJournal(journalPath, target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(journalPath); !os.IsNotExist(err) {
		t.Fatalf("truncated journal remains, stat error = %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "current executable" {
		t.Fatalf("target = %q, want original executable", got)
	}
}

func TestReconcileReplacementJournalRejectsUntrustedPaths(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "fetch.exe") + replacementJournalSuffix
	if err := os.WriteFile(journalPath, []byte(`{"staged":"../new.exe","relocated":"old.exe"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := reconcileReplacementJournal(journalPath, ""); err == nil {
		t.Fatal("reconcileReplacementJournal accepted paths outside the executable directory")
	}
}

func createZip(t *testing.T, filename string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	fw, err := zw.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
