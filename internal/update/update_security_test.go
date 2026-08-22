package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
)

func TestParseChecksumRequiresSHA256AndAllowsFilename(t *testing.T) {
	digest := sha256.Sum256([]byte("archive"))
	hexDigest := hex.EncodeToString(digest[:])

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"bare", hexDigest, false},
		{"leading whitespace and filename", " \t" + strings.ToUpper(hexDigest) + "  fetch.tar.gz", false},
		{"short", hexDigest[:63], true},
		{"non-hex", strings.Repeat("z", 64), true},
		{"invalid suffix", hexDigest + "!", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseChecksum([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseChecksum error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != digest {
				t.Fatalf("digest = %x, want %x", got, digest)
			}
		})
	}
}

func TestGetArtifactAssetsRequiresUniqueChecksumSidecar(t *testing.T) {
	name := "fetch-v1.2.3-" + runtime.GOOS + "-" + runtime.GOARCH + ".tar.gz"
	release := &Release{TagName: "v1.2.3", Assets: []Asset{{Name: name, URL: "https://example/archive"}}}
	if runtime.GOOS == "windows" {
		name = "fetch-v1.2.3-" + runtime.GOOS + "-" + runtime.GOARCH + ".zip"
		release.Assets[0].Name = name
	}
	if _, _, err := getArtifactAssets(release); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("missing sidecar error = %v", err)
	}

	release.Assets = append(release.Assets,
		Asset{Name: name + ".sha256", URL: "https://example/checksum"},
		Asset{Name: name + ".sha256", URL: "https://example/checksum-2"})
	if _, _, err := getArtifactAssets(release); err == nil || !strings.Contains(err.Error(), "duplicate checksum") {
		t.Fatalf("duplicate sidecar error = %v", err)
	}
}

func TestDownloadArtifactStreamsAndHashesWithoutContentLength(t *testing.T) {
	archive := bytes.Repeat([]byte("archive-data"), 1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for start := 0; start < len(archive); start += 17 {
			end := start + 17
			if end > len(archive) {
				end = len(archive)
			}
			_, _ = w.Write(archive[start:end])
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer server.Close()
	t.Setenv("FETCH_INTERNAL_UPDATE_URL", server.URL)

	c := client.NewClient(client.ClientConfig{})
	defer c.Close()
	path, got, size, err := downloadArtifact(t.Context(), c, server.URL+"/archive", t.TempDir(), nil, true)
	if err != nil {
		t.Fatalf("downloadArtifact: %v", err)
	}
	want := sha256.Sum256(archive)
	if got != want || size != int64(len(archive)) {
		t.Fatalf("digest/size = %x/%d, want %x/%d", got, size, want, len(archive))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, archive) {
		t.Fatal("downloaded archive differs from response")
	}
}

func TestUpdateRejectsOversizedMetadataWithoutContentLength(t *testing.T) {
	body := strings.Repeat("x", int(core.MaxUpdaterReleaseMetadataBytes)+1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, strings.NewReader(body))
	}))
	defer server.Close()
	t.Setenv("FETCH_INTERNAL_UPDATE_URL", server.URL)

	c := client.NewClient(client.ClientConfig{})
	defer c.Close()
	_, err := getLatestRelease(t.Context(), c)
	if err == nil || !strings.Contains(err.Error(), "release metadata") {
		t.Fatalf("getLatestRelease error = %v", err)
	}
}

func TestUpdateRedirectRejectsPlaintextOutsideInternalLoopback(t *testing.T) {
	t.Setenv("FETCH_INTERNAL_UPDATE_URL", "")
	u := mustURLForUpdateTest(t, "http://updates.example.test/releases")
	if err := validateUpdateURL(u); err == nil {
		t.Fatal("expected plaintext update URL to be rejected")
	}
}

func TestUpdateRedirectValidatorRejectsHTTPDowngrade(t *testing.T) {
	t.Setenv("FETCH_INTERNAL_UPDATE_URL", "https://api.github.com")
	next := mustURLForUpdateTest(t, "http://updates.example.test/releases")
	hop := client.RedirectHop{NextRequest: mustRequestForUpdateTest(t, next)}
	if err := validateUpdateRedirect(hop); err == nil {
		t.Fatal("expected HTTP redirect to be rejected")
	}
}

func mustURLForUpdateTest(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustRequestForUpdateTest(t *testing.T, u *url.URL) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestDownloadArtifactUsesPrivateTemporaryFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("archive"))
	}))
	defer server.Close()
	t.Setenv("FETCH_INTERNAL_UPDATE_URL", server.URL)

	dir := t.TempDir()
	c := client.NewClient(client.ClientConfig{})
	defer c.Close()
	path, _, _, err := downloadArtifact(t.Context(), c, server.URL, dir, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("archive path = %q, want under %q", path, dir)
	}
}
