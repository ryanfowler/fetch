package update

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/fileutil"
	"github.com/ryanfowler/fetch/internal/resolver"
)

// NetworkConfig contains the operational network policy that is safe to
// carry into update requests. Origin credentials, client certificates,
// insecure TLS, and forced protocol settings are intentionally excluded.
type NetworkConfig struct {
	CACerts          []*x509.Certificate
	ConnectTimeout   time.Duration
	ResolverEndpoint *resolver.Endpoint
	DNSServer        *url.URL
	Proxy            *url.URL
}

// Update checks the API for the latest fetch version and upgrades the current
// executable in-place, returning the exit code to use. It retains the legacy
// entry point for callers that do not need custom network policy.
func Update(ctx context.Context, p *core.Printer, timeout time.Duration, silent bool, dryRun bool) int {
	return UpdateWithConfig(ctx, p, timeout, silent, dryRun, NetworkConfig{})
}

// UpdateWithConfig applies the caller's resolver, proxy, CA, and connect
// timeout policy to metadata and artifact downloads. It does not inherit
// origin-specific authentication or TLS weakening settings.
func UpdateWithConfig(ctx context.Context, p *core.Printer, timeout time.Duration, silent bool, dryRun bool, network NetworkConfig) int {
	err := update(ctx, p, timeout, silent, dryRun, network)
	if err == nil {
		return 0
	}

	core.WriteErrorMsg(p, boundUpdateError(err))
	return 1
}

type boundedUpdateError struct {
	err error
	msg string
}

func (e boundedUpdateError) Error() string           { return e.msg }
func (e boundedUpdateError) Unwrap() error           { return e.err }
func (e boundedUpdateError) PrintTo(p *core.Printer) { p.WriteString(e.msg) }

func boundUpdateError(err error) error {
	if err == nil {
		return nil
	}
	const maxDiagnosticBytes = 4 << 10
	message := core.TerminalSafeText(err.Error())
	if len(message) > maxDiagnosticBytes {
		message = message[:maxDiagnosticBytes-len("... (truncated)")] + "... (truncated)"
	}
	return boundedUpdateError{err: err, msg: message}
}

// CheckWithConfig checks the latest release without downloading or replacing
// the executable. It uses the same bounded HTTPS and operational network
// policy as an explicit update.
func CheckWithConfig(ctx context.Context, p *core.Printer, timeout time.Duration, silent bool, network NetworkConfig) int {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeoutCause(ctx, timeout, core.ErrRequestTimedOut{Timeout: timeout})
		defer cancel()
	}

	c := client.NewClient(client.ClientConfig{
		CACerts:          network.CACerts,
		ConnectTimeout:   network.ConnectTimeout,
		ResolverEndpoint: network.ResolverEndpoint,
		DNSServer:        network.DNSServer,
		Proxy:            network.Proxy,
	})
	defer c.Close()

	exePath, err := getExecutablePath()
	if err == nil {
		var version string
		version, err = getExeVersion(ctx, exePath)
		if err == nil {
			var latest *Release
			latest, err = getLatestRelease(ctx, c)
			if err == nil {
				if latest.TagName == version {
					writeMsg(p, silent, "Already using the latest version ("+safeUpdateText(version)+").\n")
				} else if !silent {
					p.WriteString("Update available: ")
					p.WriteString(version)
					p.WriteString(" -> ")
					p.Set(core.Bold)
					p.WriteString(latest.TagName)
					p.Reset()
					p.WriteString("\n")
					p.Flush()
				}
			}
		}
	}
	if err == nil {
		return 0
	}
	core.WriteErrorMsg(p, boundUpdateError(fmt.Errorf("update check: %w", err)))
	return 1
}

func update(ctx context.Context, p *core.Printer, timeout time.Duration, silent bool, dryRun bool, network NetworkConfig) error {
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
		return fmt.Errorf("update setup: %w", err)
	}
	unlock, err := acquireLock(ctx, p, cacheDir, true, silent)
	if err != nil {
		return fmt.Errorf("update lock: %w", err)
	}
	defer unlock()

	defer func() {
		// Update the last updated time in the metadata file.
		err = updateLastAttemptTime(cacheDir, time.Now())
		if err != nil {
			msg := fmt.Sprintf("unable to record the 'last update attempt' timestamp: %s", err.Error())
			core.WriteWarningMsgIf(p, msg, silent)
		}
	}()

	// Perform the update.
	return updateInner(ctx, p, silent, dryRun, network)
}

func updateInner(ctx context.Context, p *core.Printer, silent bool, dryRun bool, network NetworkConfig) error {
	c := client.NewClient(client.ClientConfig{
		CACerts:          network.CACerts,
		ConnectTimeout:   network.ConnectTimeout,
		ResolverEndpoint: network.ResolverEndpoint,
		DNSServer:        network.DNSServer,
		Proxy:            network.Proxy,
	})
	defer c.Close()

	// Get the current executable path and verify that we have write
	// permission in order to replace the file.
	exePath, err := getExecutablePath()
	if err != nil {
		return fmt.Errorf("preflight: resolve executable: %w", err)
	}
	if !canReplaceFile(exePath) {
		return fmt.Errorf("preflight: %w", errNoWritePermission(exePath))
	}

	// Get the current version by calling `fetch --version` so that if the
	// executable was updated while we were waiting for the update lock,
	// we have the most up-to-date local version.
	version, err := getExeVersion(ctx, exePath)
	if err != nil {
		return fmt.Errorf("preflight: read current version: %w", err)
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
			p.WriteString(safeUpdateText(version))
			p.Reset()
			p.WriteString(").\n")
			p.Flush()
		}
		return nil
	}

	// Look for the artifact and its mandatory checksum sidecar before doing
	// any binary download. Asset names are exact and must be unambiguous.
	artifact, checksum, err := getArtifactAssets(latest)
	if err != nil {
		return fmt.Errorf("asset selection: %w", err)
	}

	// A dry run validates checksum availability but never downloads the
	// executable or opens an archive.
	expectedDigest, err := downloadChecksum(ctx, c, checksum.URL)
	if err != nil {
		return fmt.Errorf("checksum download: %w", err)
	}
	if dryRun {
		_ = expectedDigest
		if !silent {
			p.WriteString("Update available: ")
			p.WriteString(safeUpdateText(version))
			p.WriteString(" -> ")
			p.Set(core.Bold)
			p.WriteString(safeUpdateText(latest.TagName))
			p.Reset()
			p.WriteString("\n")
			p.Flush()
		}
		return nil
	}

	if !silent {
		p.WriteString("Downloading ")
		p.Set(core.Bold)
		p.WriteString(safeUpdateText(latest.TagName))
		p.Reset()
		p.WriteString("\n\n")
		p.Flush()
	}

	// Download into an exclusive temporary file while hashing. The archive is
	// not opened until the sidecar digest matches.
	tempDir, err := os.MkdirTemp("", "fetch-")
	if err != nil {
		return fmt.Errorf("extraction: create temporary directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	archivePath, actualDigest, contentLength, err := downloadArtifact(ctx, c, artifact.URL, tempDir, p, silent)
	if err != nil {
		return fmt.Errorf("archive download: %w", err)
	}
	if actualDigest != expectedDigest {
		return fmt.Errorf("checksum verification: SHA-256 mismatch (expected %s, got %s)",
			hex.EncodeToString(expectedDigest[:]), hex.EncodeToString(actualDigest[:]))
	}
	_ = contentLength

	archive, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening verified archive: %w", err)
	}
	err = unpackArtifact(tempDir, archive)
	closeErr := archive.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("extraction: %w", err)
	}

	// Replace the current executable in-place.
	src := filepath.Join(tempDir, getFetchFilename())
	err = selfReplace(exePath, src)
	if err != nil {
		return fmt.Errorf("replacement: %w", err)
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
	urlStr := strings.TrimRight(getUpdateURL(), "/") + "/repos/ryanfowler/fetch/releases/latest"
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid release lookup URL: %w", err)
	}
	if err := validateUpdateURL(u); err != nil {
		return nil, err
	}

	resp, err := doUpdateGET(ctx, c, u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, updateStatusError("release lookup", resp)
	}

	data, err := readUpdateBody(resp, core.MaxUpdaterReleaseMetadataBytes, "release metadata")
	if err != nil {
		return nil, err
	}
	var release Release
	if err := json.Unmarshal(data, &release); err != nil {
		return nil, fmt.Errorf("invalid release metadata: %w", err)
	}
	if release.TagName == "" {
		return nil, errors.New("release metadata contains no tag")
	}
	return &release, nil
}

func doUpdateGET(ctx context.Context, c *client.Client, u *url.URL) (*http.Response, error) {
	ctx = client.WithRedirectValidator(ctx, validateUpdateRedirect)
	req, err := c.NewRequest(ctx, client.RequestConfig{Method: http.MethodGet, URL: u})
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func readUpdateBody(resp *http.Response, max int64, subsystem string) ([]byte, error) {
	if client.WireContentLength(resp) > max {
		return nil, core.LimitError{Subsystem: subsystem, Limit: max}
	}
	data, err := core.ReadAllLimited(resp.Body, max, subsystem)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func updateStatusError(stage string, resp *http.Response) error {
	excerpt, err := core.ReadAllLimited(resp.Body, 4<<10, "update error response")
	if err != nil {
		return fmt.Errorf("%s: received status %d (%w)", stage, resp.StatusCode, err)
	}
	excerptText := strings.TrimSpace(core.TerminalSafeText(string(excerpt)))
	if excerptText == "" {
		return fmt.Errorf("%s: received status %d", stage, resp.StatusCode)
	}
	return fmt.Errorf("%s: received status %d: %s", stage, resp.StatusCode, excerptText)
}

func downloadChecksum(ctx context.Context, c *client.Client, urlStr string) ([32]byte, error) {
	var zero [32]byte
	u, err := url.Parse(urlStr)
	if err != nil {
		return zero, fmt.Errorf("invalid checksum URL: %w", err)
	}
	if err := validateUpdateURL(u); err != nil {
		return zero, err
	}
	resp, err := doUpdateGET(ctx, c, u)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, updateStatusError("checksum download", resp)
	}
	data, err := readUpdateBody(resp, core.MaxUpdaterChecksumSidecarBytes, "update checksum sidecar")
	if err != nil {
		return zero, err
	}
	return parseChecksum(data)
}

func parseChecksum(data []byte) ([32]byte, error) {
	var digest [32]byte
	trimmed := strings.TrimLeftFunc(string(data), unicode.IsSpace)
	if len(trimmed) < sha256.Size*2 {
		return digest, errors.New("checksum sidecar does not contain a 64-character SHA-256 digest")
	}
	encoded := trimmed[:sha256.Size*2]
	for i := 0; i < len(encoded); i++ {
		if !isHex(encoded[i]) {
			return digest, errors.New("checksum sidecar begins with invalid SHA-256 hex")
		}
	}
	// A sidecar may use one conventional whitespace-separated filename after
	// the digest. Reject extra fields or lines instead of silently ignoring
	// arbitrary data.
	if len(trimmed) > len(encoded) {
		if !unicode.IsSpace(rune(trimmed[len(encoded)])) {
			return digest, errors.New("checksum sidecar has invalid trailing data")
		}
		suffix := strings.TrimSpace(trimmed[len(encoded):])
		if suffix != "" {
			for _, r := range suffix {
				if unicode.IsSpace(r) || unicode.IsControl(r) {
					return digest, errors.New("checksum sidecar has invalid trailing data")
				}
			}
		}
	}
	decoded, err := hex.DecodeString(strings.ToLower(encoded))
	if err != nil {
		return digest, err
	}
	copy(digest[:], decoded)
	return digest, nil
}

func isHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

func downloadArtifact(ctx context.Context, c *client.Client, urlStr, dir string, p *core.Printer, silent bool) (string, [32]byte, int64, error) {
	var zero [32]byte
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", zero, 0, fmt.Errorf("invalid archive URL: %w", err)
	}
	if err := validateUpdateURL(u); err != nil {
		return "", zero, 0, err
	}
	resp, err := doUpdateGET(ctx, c, u)
	if err != nil {
		return "", zero, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", zero, 0, updateStatusError("archive download", resp)
	}
	if client.WireContentLength(resp) > core.MaxUpdaterArtifactBytes {
		return "", zero, 0, core.LimitError{Subsystem: "update archive", Limit: core.MaxUpdaterArtifactBytes}
	}

	file, err := os.CreateTemp(dir, ".fetch-update-archive-*")
	if err != nil {
		return "", zero, 0, err
	}
	path := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()

	body := wrapProgress(resp.Body, p, silent, resp.ContentLength)
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(body, core.MaxUpdaterArtifactBytes+1))
	if closeErr := body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", zero, written, err
	}
	if written > core.MaxUpdaterArtifactBytes {
		return "", zero, written, core.LimitError{Subsystem: "update archive", Limit: core.MaxUpdaterArtifactBytes}
	}
	if err := file.Sync(); err != nil {
		return "", zero, written, err
	}
	if err := file.Close(); err != nil {
		return "", zero, written, err
	}
	keep = true
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return path, digest, written, nil
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

// getArtifactAssets finds the platform archive and its mandatory checksum
// sidecar. Duplicate matches are rejected instead of being selected by order.
func getArtifactAssets(release *Release) (Asset, Asset, error) {
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	name := fmt.Sprintf("fetch-%s-%s-%s.%s", release.TagName, runtime.GOOS, runtime.GOARCH, ext)
	checksumName := name + ".sha256"

	var archive, checksum Asset
	var archiveMatches, checksumMatches int
	for _, asset := range release.Assets {
		switch asset.Name {
		case name:
			archive = asset
			archiveMatches++
		case checksumName:
			checksum = asset
			checksumMatches++
		}
	}
	if archiveMatches == 0 {
		return Asset{}, Asset{}, errNoReleaseArtifact{}
	}
	if archiveMatches > 1 {
		return Asset{}, Asset{}, errors.New("release contains duplicate archive assets")
	}
	if checksumMatches == 0 {
		return Asset{}, Asset{}, errors.New("release archive has no matching SHA-256 checksum sidecar")
	}
	if checksumMatches > 1 {
		return Asset{}, Asset{}, errors.New("release contains duplicate checksum assets")
	}
	if archive.URL == "" || checksum.URL == "" {
		return Asset{}, Asset{}, errors.New("release asset has an empty download URL")
	}
	return archive, checksum, nil
}

func validateUpdateURL(u *url.URL) error {
	if u == nil || u.Hostname() == "" {
		return errors.New("update URL must have a host")
	}
	if u.User != nil {
		return errors.New("update URL must not contain credentials")
	}
	if u.Fragment != "" {
		return errors.New("update URL must not contain a fragment")
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	// A loopback HTTP endpoint is available only through the explicit internal
	// test override. Production update URLs remain HTTPS-only.
	if strings.EqualFold(u.Scheme, "http") && os.Getenv("FETCH_INTERNAL_UPDATE_URL") != "" {
		host := u.Hostname()
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("update URL must use HTTPS: %s", core.RedactedURL(u))
}

func validateUpdateRedirect(hop client.RedirectHop) error {
	if hop.Response != nil {
		location := hop.Response.Header.Get("Location")
		if location != "" {
			if _, err := url.Parse(location); err != nil {
				return fmt.Errorf("invalid update redirect location: %w", err)
			}
		}
	}
	if err := validateUpdateURL(hop.NextRequest.URL); err != nil {
		return fmt.Errorf("update redirect rejected: %w", err)
	}
	return nil
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

func safeUpdateText(value string) string {
	const maxBytes = 256
	if len(value) > maxBytes {
		value = value[:maxBytes]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
		value += "..."
	}
	return core.TerminalSafeText(value)
}

func writeUpdateSuccess(p *core.Printer, silent bool, oldVersion, newVersion string) {
	if silent {
		return
	}

	p.WriteString("Updated fetch: ")
	p.WriteString(safeUpdateText(oldVersion))
	p.WriteString(" -> ")
	p.Set(core.Bold)
	p.WriteString(safeUpdateText(newVersion))
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
		p.WriteString(url.PathEscape(compareRef))
		p.WriteString("...")
		p.WriteString(url.PathEscape(newVersion))
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

	unlock, err := acquireLock(ctx, p, dir, false, true)
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

	err = fileutil.AtomicReplaceFile(tempPath, path)
	return err
}

func acquireLock(ctx context.Context, p *core.Printer, dir string, block bool, silent bool) (func(), error) {
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
			core.WriteWarningMsgIf(p, "waiting on lock to begin updating\n", silent)
		}

		mult := time.Duration(min(i+1, 10))
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
