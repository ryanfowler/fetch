package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
)

// Update checks the API for the latest fetch version and upgrades the current
// executable in-place, returning the exit code to use.
func Update(ctx context.Context, p *core.Printer, timeout time.Duration, silent bool) int {
	err := update(ctx, p, timeout, silent)
	if err == nil {
		return 0
	}

	p.Set(core.Bold)
	p.Set(core.Red)
	p.WriteString("error")
	p.Reset()
	p.WriteString(": ")
	p.WriteString(err.Error())
	p.WriteString("\n")
	p.Flush()
	return 1
}

func update(ctx context.Context, p *core.Printer, timeout time.Duration, silent bool) error {
	if timeout > 0 {
		// Ensure the context is cancelled after the provided timeout.
		var cancel context.CancelFunc
		cause := core.ErrRequestTimedOut{Timeout: timeout}
		ctx, cancel = context.WithTimeoutCause(ctx, timeout, cause)
		defer cancel()
	}

	// Obtain the update lock.
	cacheDir, err := getCacheDir()
	if err != nil {
		return err
	}
	unlock, err := acquireLock(ctx, p, cacheDir, true)
	if err != nil {
		return err
	}
	defer unlock()

	// Perform the update.
	err = updateInner(ctx, p, silent)
	if err != nil {
		return err
	}

	// Update the last updated time in the metadata file.
	err = updateLastUpdatedTime(cacheDir, time.Now())
	if err != nil {
		writeWarning(p, fmt.Sprintf("unable to update the 'last updated' timestamp: %s", err.Error()))
	}

	return nil
}

func updateInner(ctx context.Context, p *core.Printer, silent bool) error {
	c := client.NewClient(client.ClientConfig{})

	// Get the current version by calling `fetch --version` so that if the
	// executable was updated while we were waiting for the update lock,
	// we have the most up-to-date local version.
	exePath, err := getExecutablePath()
	if err != nil {
		return err
	}
	version, err := getExeVersion(ctx, exePath)
	if err != nil {
		return err
	}

	writeInfo(p, silent, "fetching latest release tag")
	latest, err := getLatestRelease(ctx, c)
	if err != nil {
		return fmt.Errorf("fetching latest release: %w", err)
	}

	if latest.TagName == version {
		// Already using the latest version, exit successfully.
		writeInfo(p, silent, fmt.Sprintf("currently using the latest version (%s)", version))
		return nil
	}

	// Look for the artifact URL for our OS and architecture.
	artifactURL := getArtifactURL(latest)
	if artifactURL == "" {
		return fmt.Errorf("no %s/%s artifact found for %s",
			runtime.GOOS, runtime.GOARCH, latest.TagName)
	}

	writeInfo(p, silent, fmt.Sprintf("downloading latest version (%s)", latest.TagName))
	rc, err := getArtifactReader(ctx, c, artifactURL)
	if err != nil {
		return fmt.Errorf("fetching artifact: %w", err)
	}
	defer rc.Close()

	// Create a temporary directory, and unpack the artifact into it.
	tempDir, err := os.MkdirTemp("", "fetch-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	err = unpackArtifact(tempDir, rc)
	if err != nil {
		return err
	}

	// Replace the current executable in-place.
	src := filepath.Join(tempDir, getFetchFilename())
	err = selfReplace(exePath, src)
	if err != nil {
		return err
	}

	msg := fmt.Sprintf("fetch successfully updated (%s -> %s)", version, latest.TagName)
	writeInfo(p, silent, msg)
	return nil
}

func getExeVersion(ctx context.Context, path string) (string, error) {
	var buf strings.Builder
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return "", err
	}

	_, version, _ := strings.Cut(buf.String(), " ")
	return strings.TrimSpace(version), nil
}

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// getLatestRelease returns the latest release, as reported by the API.
func getLatestRelease(ctx context.Context, c *client.Client) (*Release, error) {
	urlStr := getUpdateURL() + "/repos/ryanfowler/fetch/releases/latest"
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	cfg := client.RequestConfig{
		Method: "GET",
		URL:    u,
	}
	req, err := c.NewRequest(ctx, cfg)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("received status: %d", resp.StatusCode)
	}

	var release Release
	err = json.NewDecoder(resp.Body).Decode(&release)
	if err != nil {
		return nil, err
	}
	if release.TagName == "" {
		return nil, errors.New("no tag found")
	}

	return &release, nil
}

// getArtifactReader returns an io.ReadCloser of the artifact data.
func getArtifactReader(ctx context.Context, c *client.Client, urlStr string) (io.ReadCloser, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	cfg := client.RequestConfig{
		Method: "GET",
		URL:    u,
	}
	req, err := c.NewRequest(ctx, cfg)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("downloading artifact: received status: %d", resp.StatusCode)
	}

	return resp.Body, nil
}

// getArtifactURL finds and returns the artifact URL for the current OS and
// architecture. If no URL can be found, it returns an empty string.
func getArtifactURL(release *Release) string {
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	name := fmt.Sprintf("fetch-%s-%s-%s.%s",
		release.TagName, runtime.GOOS, runtime.GOARCH, ext)

	for _, asset := range release.Assets {
		if asset.Name == name {
			return asset.URL
		}
	}
	return ""
}

// getExecutablePath returns the current executable path, following any symlinks.
func getExecutablePath() (string, error) {
	binPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(binPath)
}

func getFetchFilename() string {
	name := "fetch"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func writeInfo(p *core.Printer, silent bool, s string) {
	if silent {
		return
	}

	p.Set(core.Bold)
	p.Set(core.Green)
	p.WriteString("info")
	p.Reset()
	p.WriteString(": ")

	p.WriteString(s)
	p.WriteString("\n")
	p.Flush()
}

func writeWarning(p *core.Printer, s string) {
	p.Set(core.Bold)
	p.Set(core.Yellow)
	p.WriteString("warning")
	p.Reset()
	p.WriteString(": ")

	p.WriteString(s)
	p.WriteString("\n")
	p.Flush()
}

// randomString returns a random string of lower-case letters of length "n".
func randomString(n int) string {
	var sb strings.Builder
	sb.Grow(n)

	const letters = "abcdefghijklmnopqrstuvwxyz"
	for range n {
		b := letters[rand.IntN(len(letters))]
		sb.WriteByte(b)
	}

	return sb.String()
}

// getUpdateURL returns the URL to use to obtain the latest fetch version info.
// If the FETCH_INTERNAL_UPDATE_URL environment variable is set, it uses that
// value.
func getUpdateURL() string {
	if env := os.Getenv("FETCH_INTERNAL_UPDATE_URL"); env != "" {
		return env
	}
	return "https://api.github.com"
}

// createTempFilePath returns a path name in the format:
// "{dir}/.fetch.{16_rand_letters}{suffix}"
func createTempFilePath(dir, suffix string) string {
	name := ".fetch." + randomString(16) + suffix
	return filepath.Join(dir, name)
}

// copyFile copies the data from dst to src, creating the destination file with
// the same file mode if necessary.
func copyFile(dst, src string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	info, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	return dstFile.Sync()
}

type metadata struct {
	LastUpdatedAt time.Time `json:"last_updated_at"`
}

// NeedsUpdate returns true if the application hasn't checked for an update
// longer than the provided duration.
func NeedsUpdate(ctx context.Context, p *core.Printer, dur time.Duration) (bool, error) {
	dir, err := getCacheDir()
	if err != nil {
		return false, err
	}

	unlock, err := acquireLock(ctx, p, dir, false)
	if err != nil {
		return false, err
	}
	if unlock == nil {
		// Lock is already acquired, assume no update is required.
		return false, nil
	}
	defer unlock()

	path := filepath.Join(dir, "metadata.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// File doesn't exist, assume update is needed.
		return true, nil
	}
	if err != nil {
		return false, err
	}

	var m metadata
	if err = json.Unmarshal(data, &m); err != nil {
		// Invalid data, assume update is needed.
		return true, nil
	}

	return time.Since(m.LastUpdatedAt) > dur, nil
}

func getCacheDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, "fetch")
	err = os.MkdirAll(path, 0755)
	if err != nil {
		return "", err
	}

	return path, nil
}

func updateLastUpdatedTime(dir string, now time.Time) error {
	data, err := json.Marshal(metadata{LastUpdatedAt: now.UTC()})
	if err != nil {
		return err
	}

	path := filepath.Join(dir, "metadata.json")
	tempPath := path + ".__temp"
	err = os.WriteFile(tempPath, data, 0666)
	if err != nil {
		return err
	}

	return os.Rename(tempPath, path)
}

func acquireLock(ctx context.Context, p *core.Printer, dir string, block bool) (func(), error) {
	path := filepath.Join(dir, ".update-lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}

	for i := 0; ; i++ {
		ok, err := tryLockFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		if ok {
			return func() {
				unlockFile(f)
				f.Close()
			}, nil
		}
		if !block {
			f.Close()
			return nil, nil
		}

		if i == 0 {
			writeWarning(p, "waiting on lock to begin updating\n")
		}

		mult := time.Duration(min(i, 10))
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(mult * 50 * time.Millisecond):
		}
	}
}
