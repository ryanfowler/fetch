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
func Update(ctx context.Context, p *core.Printer, timeout time.Duration, silent bool, dryRun bool) int {
	err := update(ctx, p, timeout, silent, dryRun)
	if err == nil {
		return 0
	}

	core.WriteErrorMsg(p, err)
	return 1
}

func update(ctx context.Context, p *core.Printer, timeout time.Duration, silent bool, dryRun bool) error {
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

	defer func() {
		// Update the last updated time in the metadata file.
		err = updateLastAttemptTime(cacheDir, time.Now())
		if err != nil {
			msg := fmt.Sprintf("unable to record the 'last update attempt' timestamp: %s", err.Error())
			core.WriteWarningMsg(p, msg)
		}
	}()

	// Perform the update.
	return updateInner(ctx, p, silent, dryRun)
}

func updateInner(ctx context.Context, p *core.Printer, silent bool, dryRun bool) error {
	c := client.NewClient(client.ClientConfig{})

	// Get the current executable path and verify that we have write
	// permission in order to replace the file.
	exePath, err := getExecutablePath()
	if err != nil {
		return err
	}
	if !canReplaceFile(exePath) {
		return errNoWritePermission(exePath)
	}

	// Get the current version by calling `fetch --version` so that if the
	// executable was updated while we were waiting for the update lock,
	// we have the most up-to-date local version.
	version, err := getExeVersion(ctx, exePath)
	if err != nil {
		return err
	}

	writeMsg(p, silent, "Fetching latest release...\n")
	latest, err := getLatestRelease(ctx, c)
	if err != nil {
		return fmt.Errorf("unable to fetch the latest release: %w", err)
	}

	if latest.TagName == version {
		// Already using the latest version, exit successfully.
		if !silent {
			p.WriteString("Already using the latest version (")
			p.Set(core.Bold)
			p.WriteString(version)
			p.Reset()
			p.WriteString(").\n")
			p.Flush()
		}
		return nil
	}

	if dryRun {
		if !silent {
			p.WriteString("Update available: ")
			p.WriteString(version)
			p.WriteString(" -> ")
			p.Set(core.Bold)
			p.WriteString(latest.TagName)
			p.Reset()
			p.WriteString("\n")
			p.Flush()
		}
		return nil
	}

	// Look for the artifact URL for our OS and architecture.
	artifactURL := getArtifactURL(latest)
	if artifactURL == "" {
		return errNoReleaseArtifact{}
	}

	if !silent {
		p.WriteString("Downloading ")
		p.Set(core.Bold)
		p.WriteString(latest.TagName)
		p.Reset()
		p.WriteString("\n\n")
		p.Flush()
	}

	rc, contentLength, err := getArtifactReader(ctx, c, artifactURL)
	if err != nil {
		return fmt.Errorf("fetching artifact: %w", err)
	}

	// Create a temporary directory, and unpack the artifact into it.
	tempDir, err := os.MkdirTemp("", "fetch-")
	if err != nil {
		rc.Close()
		return err
	}
	defer os.RemoveAll(tempDir)

	// Wrap reader with progress indicator if appropriate.
	rc = wrapProgress(rc, p, silent, contentLength)

	err = unpackArtifact(tempDir, rc)
	rc.Close()
	if err != nil {
		return err
	}

	// Replace the current executable in-place.
	src := filepath.Join(tempDir, getFetchFilename())
	err = selfReplace(exePath, src)
	if err != nil {
		return err
	}

	writeUpdateSuccess(p, silent, version, latest.TagName)
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

// getArtifactReader returns an io.ReadCloser of the artifact data and the
// content length (or -1 if unknown).
func getArtifactReader(ctx context.Context, c *client.Client, urlStr string) (io.ReadCloser, int64, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, 0, err
	}

	cfg := client.RequestConfig{
		Method: "GET",
		URL:    u,
	}
	req, err := c.NewRequest(ctx, cfg)
	if err != nil {
		return nil, 0, err
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, 0, fmt.Errorf("downloading artifact: received status: %d", resp.StatusCode)
	}

	return resp.Body, resp.ContentLength, nil
}

// wrapProgress wraps the reader with a progress indicator if appropriate.
func wrapProgress(rc io.ReadCloser, p *core.Printer, silent bool, contentLength int64) io.ReadCloser {
	if silent || !core.IsStderrTerm {
		return rc
	}
	if contentLength > 0 {
		return newUpdateProgress(rc, p, contentLength)
	}
	return newUpdateSpinner(rc, p)
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

func writeMsg(p *core.Printer, silent bool, s string) {
	if silent {
		return
	}
	p.WriteString(s)
	p.Flush()
}

func writeUpdateSuccess(p *core.Printer, silent bool, oldVersion, newVersion string) {
	if silent {
		return
	}

	p.WriteString("Updated fetch: ")
	p.WriteString(oldVersion)
	p.WriteString(" -> ")
	p.Set(core.Bold)
	p.WriteString(newVersion)
	p.Reset()
	p.WriteString("\n")

	compareRef := oldVersion
	if !isVersionTag(compareRef) {
		compareRef = core.GetVCSRevision()
	}
	if compareRef != "" {
		p.WriteString("\nChangelog: ")
		p.Set(core.Underline)
		p.WriteString("https://github.com/ryanfowler/fetch/compare/")
		p.WriteString(compareRef)
		p.WriteString("...")
		p.WriteString(newVersion)
		p.Reset()
		p.WriteString("\n")
	}
	p.Flush()
}

// isVersionTag returns true if s matches the pattern vX.Y.Z where X, Y, and Z
// are non-empty sequences of digits.
func isVersionTag(s string) bool {
	if len(s) < 6 || s[0] != 'v' {
		return false
	}
	dots := 0
	for i := 1; i < len(s); i++ {
		if s[i] == '.' {
			if i == 1 || i == len(s)-1 || s[i-1] == '.' {
				return false
			}
			dots++
		} else if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return dots == 2
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
	LastAttemptAt time.Time `json:"last_attempt_at"`
}

// ShouldAttemptUpdate returns true if the application hasn't checked for an
// update longer than the provided duration.
func ShouldAttemptUpdate(ctx context.Context, p *core.Printer, dur time.Duration) (bool, error) {
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

	return time.Since(m.LastAttemptAt) > dur, nil
}

func getCacheDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, "fetch")
	err = os.MkdirAll(path, 0700)
	if err != nil {
		return "", err
	}

	return path, nil
}

func updateLastAttemptTime(dir string, now time.Time) error {
	data, err := json.Marshal(metadata{LastAttemptAt: now.UTC()})
	if err != nil {
		return err
	}

	path := filepath.Join(dir, "metadata.json")
	f, err := os.CreateTemp(dir, ".metadata-*.tmp")
	if err != nil {
		return err
	}
	tempPath := f.Name()
	defer func() {
		// Clean up temp file on error.
		if err != nil {
			os.Remove(tempPath)
		}
	}()
	_, err = f.Write(data)
	if err2 := f.Close(); err == nil {
		err = err2
	}
	if err != nil {
		return err
	}

	err = os.Rename(tempPath, path)
	return err
}

func acquireLock(ctx context.Context, p *core.Printer, dir string, block bool) (func(), error) {
	path := filepath.Join(dir, ".update-lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
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
			core.WriteWarningMsg(p, "waiting on lock to begin updating\n")
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

type errNoReleaseArtifact struct{}

func (err errNoReleaseArtifact) Error() string {
	return fmt.Sprintf("no release artifact found for %s/%s", runtime.GOOS, runtime.GOARCH)
}

func (err errNoReleaseArtifact) PrintTo(p *core.Printer) {
	p.WriteString("no release artifact found for ")
	p.Set(core.Bold)
	p.WriteString(runtime.GOOS)
	p.Reset()
	p.WriteString("/")
	p.Set(core.Bold)
	p.WriteString(runtime.GOARCH)
	p.Reset()

	p.WriteString("\n\nTry compiling from source by running: '")
	p.Set(core.Dim)
	p.WriteString("go install github.com/ryanfowler/fetch@latest")
	p.Reset()
	p.WriteString("'")
}

type errNoWritePermission string

func (err errNoWritePermission) Error() string {
	return fmt.Sprintf("the current process does not have write permission to '%s'", string(err))
}

func (err errNoWritePermission) PrintTo(p *core.Printer) {
	p.WriteString("the current process does not have write permission to '")
	p.Set(core.Dim)
	p.WriteString(string(err))
	p.Reset()
	p.WriteString("'")
}
