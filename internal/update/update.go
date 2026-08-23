package update

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
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
	message := core.RedactedErrorText(err)
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
	background := os.Getenv("FETCH_INTERNAL_AUTO_UPDATE") == "1"
	unlock, err := acquireLock(ctx, p, cacheDir, !background, silent)
	if err != nil {
		return fmt.Errorf("update lock: %w", err)
	}
	if unlock == nil {
		// Another automatic updater owns the lock. This is a successful,
		// nonblocking no-op and must not update the last-attempt timestamp.
		return nil
	}
	defer unlock()

	// Perform the update. Record an attempt only after the executable
	// preflight has succeeded and a real release lookup starts. Dry runs,
	// lock contention, and preflight failures never modify updater metadata.
	attemptStarted := false
	err = updateInner(ctx, p, silent, dryRun, network, func() { attemptStarted = true })
	if !dryRun && attemptStarted {
		if metadataErr := updateLastAttemptTime(cacheDir, time.Now()); metadataErr != nil {
			msg := fmt.Sprintf("unable to record the 'last update attempt' timestamp: %s", metadataErr.Error())
			core.WriteWarningMsgIf(p, msg, silent)
		}
	}
	return err
}

func updateInner(ctx context.Context, p *core.Printer, silent bool, dryRun bool, network NetworkConfig, markAttempt func()) error {
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
	if info, statErr := os.Lstat(exePath); statErr != nil {
		return fmt.Errorf("preflight: inspect executable: %w", statErr)
	} else if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("preflight: executable destination is not a regular file")
	}
	if err := validateReplacementDirectory(exePath); err != nil {
		return fmt.Errorf("preflight: %w", err)
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
	if markAttempt != nil {
		markAttempt()
	}
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
	if err := os.Chmod(tempDir, 0700); err != nil {
		_ = os.RemoveAll(tempDir)
		return fmt.Errorf("extraction: secure temporary directory: %w", err)
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
	if err := validateStagedExecutable(ctx, src); err != nil {
		return fmt.Errorf("extraction: validate staged executable: %w", err)
	}
	err = selfReplace(exePath, src)
	if err != nil {
		var committed *fileutil.CommittedError
		if errors.As(err, &committed) {
			core.WriteWarningMsgIf(p, "replacement committed, but cleanup did not finish: "+committed.Error(), silent)
		} else {
			return fmt.Errorf("replacement: %w", err)
		}
	}

	writeUpdateSuccess(p, silent, version, latest.TagName)
	return nil
}

func getExeVersion(ctx context.Context, path string) (string, error) {
	return probeExecutableVersion(ctx, path)
}

// validateStagedExecutable checks the candidate before it can replace the
// running binary. The command receives no stdin and its output is bounded so
// a malicious or broken candidate cannot hang or exhaust the updater.
func validateStagedExecutable(parent context.Context, path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("staged executable is not a regular file")
	}
	if info.Size() == 0 {
		return errors.New("staged executable is empty")
	}
	if err := os.Chmod(path, 0755); err != nil {
		return err
	}
	_, err = probeExecutableVersion(parent, path)
	return err
}

const (
	executableProbeTimeout     = 5 * time.Second
	executableProbeOutputLimit = 4 << 10
)

// probeExecutableVersion runs an executable's --version command in a bounded,
// contained process environment. It is used for both the current executable
// and update candidates, so neither preflight path can hang or retain
// unbounded output from an untrusted binary.
func probeExecutableVersion(parent context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, executableProbeTimeout)
	defer cancel()
	stdout := core.NewBoundedBuffer(executableProbeOutputLimit, "executable output")
	stderr := core.NewBoundedBuffer(executableProbeOutputLimit, "executable error output")
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return "", err
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		return "", err
	}
	cmd := exec.Command(path, "--version")
	cmd.Stdin = nil
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter
	if err := configureProbeProcess(cmd); err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		_ = stderrReader.Close()
		_ = stderrWriter.Close()
		return "", err
	}
	if err := cmd.Start(); err != nil {
		releaseProbeProcess(cmd)
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		_ = stderrReader.Close()
		_ = stderrWriter.Close()
		return "", fmt.Errorf("start --version: %w", err)
	}
	// os/exec does not copy output when *os.File values are supplied. Close
	// the parent write ends immediately so descendants cannot keep the updater
	// waiting on an os/exec pipe-copy goroutine.
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	stdoutDone := make(chan struct{})
	stdoutErrCh := make(chan error, 1)
	stderrDone := make(chan struct{})
	stderrErrCh := make(chan error, 1)
	go func() {
		stdoutErrCh <- drainProbeOutput(stdoutReader, stdout)
		close(stdoutDone)
	}()
	go func() {
		stderrErrCh <- drainProbeOutput(stderrReader, stderr)
		close(stderrDone)
	}()

	if err := attachProbeProcess(cmd); err != nil {
		terminateProbeProcess(cmd)
		_ = cmd.Wait()
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
		<-stdoutDone
		<-stderrDone
		<-stdoutErrCh
		<-stderrErrCh
		releaseProbeProcess(cmd)
		return "", err
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	var runErr error
	select {
	case runErr = <-waitCh:
		// Let ordinary output drain, but do not let a descendant holding a
		// descriptor open extend validation.
		select {
		case <-stdoutDone:
		case <-time.After(100 * time.Millisecond):
		}
		select {
		case <-stderrDone:
		case <-time.After(100 * time.Millisecond):
		}
	case <-ctx.Done():
		terminateProbeProcess(cmd)
		runErr = <-waitCh
	}
	// The candidate may have created children after it reported its version.
	// Tear down the containment group/job on both success and failure.
	terminateProbeProcess(cmd)
	_ = stdoutReader.Close()
	_ = stderrReader.Close()
	stdoutErr := <-stdoutErrCh
	stderrErr := <-stderrErrCh
	releaseProbeProcess(cmd)
	if runErr != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("--version timed out: %w", ctx.Err())
		}
		return "", fmt.Errorf("--version failed: %w", runErr)
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("--version timed out: %w", ctx.Err())
	}
	if stdoutErr != nil {
		return "", fmt.Errorf("--version output exceeded limit: %w", stdoutErr)
	}
	if stderrErr != nil {
		return "", fmt.Errorf("--version error output exceeded limit: %w", stderrErr)
	}
	fields := strings.Fields(string(stdout.Bytes()))
	if len(fields) != 2 || fields[0] != "fetch" || fields[1] == "" {
		return "", fmt.Errorf("--version reported an unexpected program identity")
	}
	return fields[1], nil
}

func drainProbeOutput(r io.Reader, dst *core.BoundedBuffer) error {
	buf := make([]byte, 32<<10)
	var writeErr error
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, dstErr := dst.Write(buf[:n]); dstErr != nil && writeErr == nil {
				writeErr = dstErr
			}
		}
		if err != nil {
			return writeErr
		}
	}
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

// getUpdateURL returns the URL to use to obtain the latest fetch version info.
// If the FETCH_INTERNAL_UPDATE_URL environment variable is set, it uses that
// value.
func getUpdateURL() string {
	if env := os.Getenv("FETCH_INTERNAL_UPDATE_URL"); env != "" {
		return env
	}
	return "https://api.github.com"
}

const (
	updateMetadataSchemaVersion = 1
	maxUpdateMetadataBytes      = 16 << 10
)

type metadata struct {
	SchemaVersion int       `json:"schema_version"`
	LastAttemptAt time.Time `json:"last_attempt_at"`
}

// ShouldAttemptUpdate returns true if the application has not checked for an
// update within dur. Metadata is advisory state. A corrupt, stale, future, or
// symlinked metadata file is treated as a due check instead of blocking the
// requested fetch operation.
func ShouldAttemptUpdate(ctx context.Context, p *core.Printer, dur time.Duration) (bool, error) {
	if dur < 0 {
		return false, nil
	}
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
	m, err := readMetadata(path)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		// Metadata is not part of the request's correctness. If it cannot be
		// read, make the next check eligible and let the caller continue.
		return true, nil
	}
	if m.SchemaVersion != updateMetadataSchemaVersion || m.LastAttemptAt.IsZero() {
		return true, nil
	}
	now := time.Now()
	// A clock jump into the future must not suppress update checks for an
	// arbitrary length of time. Treat timestamps outside a small skew window
	// as invalid metadata.
	if m.LastAttemptAt.Before(time.Unix(0, 0)) || m.LastAttemptAt.After(now) {
		return true, nil
	}
	return now.Sub(m.LastAttemptAt) >= dur, nil
}

func readMetadata(path string) (metadata, error) {
	var m metadata
	info, err := os.Lstat(path)
	if err != nil {
		return m, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return m, errors.New("update metadata is not a regular file")
	}
	if info.Size() > maxUpdateMetadataBytes {
		return m, core.LimitError{Subsystem: "update metadata", Limit: maxUpdateMetadataBytes}
	}
	f, err := openUpdateMetadata(path)
	if err != nil {
		return m, err
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return m, err
	}
	if !openedInfo.Mode().IsRegular() {
		return m, errors.New("update metadata is not a regular file")
	}
	data, err := core.ReadAllLimited(f, maxUpdateMetadataBytes, "update metadata")
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, err
	}
	return m, nil
}

func getCacheDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, "fetch")
	if err := os.MkdirAll(path, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("update cache directory is not a real directory")
	}
	if err := os.Chmod(path, 0700); err != nil {
		return "", err
	}
	return path, nil
}

func updateLastAttemptTime(dir string, now time.Time) error {
	data, err := json.Marshal(metadata{SchemaVersion: updateMetadataSchemaVersion, LastAttemptAt: now.UTC()})
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
	if syncErr := f.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}

	if err = fileutil.AtomicReplaceFileNoSymlink(tempPath, path); err != nil {
		return err
	}
	// Directory sync is best effort. The atomic rename is the correctness
	// boundary, while durability depends on the platform and filesystem.
	_ = fileutil.SyncDir(dir)
	return nil
}

func acquireLock(ctx context.Context, p *core.Printer, dir string, block bool, silent bool) (func(), error) {
	if block {
		// Explicit updates may wait, but never indefinitely. Automatic updates
		// use block=false and remain nonblocking.
		lockCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		ctx = lockCtx
	}
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
			if block {
				return nil, fmt.Errorf("timed out waiting for update lock: %w", ctx.Err())
			}
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
