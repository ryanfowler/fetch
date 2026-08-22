//go:build !windows

package integration_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseInstallerInstallsVerifiedGoArtifactAtomically(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is required")
	}
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("tar is required")
	}

	tag := "v9.9.9"
	archiveName := fmt.Sprintf("fetch-%s-%s-%s.tar.gz", tag, runtime.GOOS, runtime.GOARCH)
	archive := installerTestArchive(t)
	digest := sha256.Sum256(archive)
	checksum := []byte(hex.EncodeToString(digest[:]) + "  " + archiveName + "\n")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		switch r.URL.Path {
		case "/latest":
			base := "http://" + r.Host
			metadata := map[string]any{
				"tag_name": tag,
				"assets": []map[string]string{
					{"name": archiveName, "browser_download_url": base + "/archive"},
					{"name": archiveName + ".sha256", "browser_download_url": base + "/checksum"},
				},
			}
			var err error
			body, err = json.Marshal(metadata)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case "/archive":
			body = archive
		case "/checksum":
			body = checksum
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	defer server.Close()

	root := filepath.Dir(filepath.Dir(mustInstallerCallerFile(t)))
	installDir := filepath.Join(t.TempDir(), "bin")
	home := t.TempDir()
	newInstaller := func() *exec.Cmd {
		cmd := exec.Command("bash", filepath.Join(root, "install.sh"))
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
			"FETCH_INSTALL_API_URL="+server.URL+"/latest",
			"FETCH_INSTALL_ALLOW_HTTP=1",
			"FETCH_INSTALL_DIR="+installDir,
			"HOME="+home,
			"SHELL=/bin/sh",
			"PATH=/usr/bin:/bin",
		)
		return cmd
	}

	output, err := runInstaller(t, newInstaller())
	if err != nil {
		t.Fatalf("installer failed: %v\n%s", err, output)
	}
	installed, err := os.ReadFile(filepath.Join(installDir, "fetch"))
	if err != nil {
		t.Fatalf("read installed executable: %v", err)
	}
	if !bytes.Equal(installed, []byte("#!/bin/sh\nprintf 'fetch v9.9.9\\n'\n")) {
		t.Fatalf("installed executable differs from verified artifact: %q", installed)
	}

	if err := os.Remove(filepath.Join(installDir, "fetch")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(installDir, "fetch")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	output, err = runInstaller(t, newInstaller())
	if err == nil || !strings.Contains(string(output), "symlink target") {
		t.Fatalf("symlink target result = %v, output=%s", err, output)
	}
	data, readErr := os.ReadFile(outside)
	if readErr != nil || string(data) != "keep" {
		t.Fatalf("symlink target was modified: err=%v data=%q", readErr, data)
	}
}

func installerTestArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gz)
	payload := []byte("#!/bin/sh\nprintf 'fetch v9.9.9\\n'\n")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "fetch", Mode: 0755, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func runInstaller(t *testing.T, cmd *exec.Cmd) ([]byte, error) {
	t.Helper()
	return cmd.CombinedOutput()
}

func mustInstallerCallerFile(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return file
}
