//go:build windows

package update

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
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

func TestUnpackArtifactFile_ExtractsNearLimitDiskBackedArchive(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "update.zip")
	size := createNearLimitZip(t, archivePath)
	if size < core.MaxUpdaterArtifactBytes-(1<<20) {
		t.Fatalf("archive size = %d, want within 1 MiB of the compressed limit", size)
	}

	archive, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()

	dir := t.TempDir()
	if err := unpackArtifactFile(dir, archive, size); err != nil {
		t.Fatalf("unpackArtifactFile: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, getFetchFilename()))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "candidate" {
		t.Fatalf("extracted content = %q, want candidate", got)
	}
}

func TestUnpackArtifactFile_RejectsCompressedLimitOverflow(t *testing.T) {
	archive, err := os.CreateTemp(t.TempDir(), "update.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()

	if err := archive.Truncate(core.MaxUpdaterArtifactBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := unpackArtifactFile(t.TempDir(), archive, core.MaxUpdaterArtifactBytes+1); err == nil {
		t.Fatal("unpackArtifactFile accepted an oversized compressed archive")
	}
}

func TestUnpackArtifact_CleansSpoolAfterExtractionError(t *testing.T) {
	dir := t.TempDir()
	if err := unpackArtifact(dir, bytes.NewReader([]byte("not a zip archive"))); err == nil {
		t.Fatal("unpackArtifact accepted an invalid archive")
	}
	paths, err := filepath.Glob(filepath.Join(dir, ".fetch-update-archive-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("temporary archive files remain after extraction failure: %v", paths)
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
		info, targetErr := os.Stat(target)
		_, journalErr := os.Lstat(journalPath)
		if targetErr == nil && info.Size() > 0 && os.IsNotExist(journalErr) {
			break
		}
		if time.Now().After(deadline) {
			if targetErr == nil && info.Size() > 0 {
				t.Fatalf("replacement journal remains, stat error = %v", journalErr)
			}
			t.Fatalf("recovery child did not finish replacement: target stat error = %v, journal stat error = %v", targetErr, journalErr)
		}
		time.Sleep(20 * time.Millisecond)
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

// createNearLimitZip leaves a sparse gap between the local entry and the
// central directory. ZIP permits this gap, which makes the archive nearly the
// compressed-size limit without requiring a large in-memory test fixture.
func createNearLimitZip(t *testing.T, path string) int64 {
	t.Helper()
	name := getFetchFilename()
	content := []byte("candidate")
	data := createZip(t, name, content)
	eocdOffset := bytes.LastIndex(data, []byte("PK\x05\x06"))
	if eocdOffset < 0 || eocdOffset+22 > len(data) {
		t.Fatalf("unexpected ZIP layout: missing EOCD")
	}
	centralOffset := int64(binary.LittleEndian.Uint32(data[eocdOffset+16 : eocdOffset+20]))
	if centralOffset < 0 || centralOffset+4 > int64(eocdOffset) ||
		!bytes.Equal(data[centralOffset:centralOffset+4], []byte("PK\x01\x02")) {
		t.Fatalf("unexpected ZIP layout: invalid central-directory offset")
	}

	targetSize := core.MaxUpdaterArtifactBytes - 1
	gap := targetSize - int64(len(data))
	if gap <= 0 {
		t.Fatalf("test archive is already too large: %d", len(data))
	}
	centralOffset += gap
	binary.LittleEndian.PutUint32(data[eocdOffset+16:eocdOffset+20], uint32(centralOffset))

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	closeFile := func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}
	defer closeFile()
	prefixLen := centralOffset - gap
	if _, err := f.Write(data[:prefixLen]); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(targetSize); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(centralOffset, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data[prefixLen:]); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	return targetSize
}
