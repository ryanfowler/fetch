// Package parity provides the differential test harness used during the Go
// migration. It deliberately treats the Rust implementation as an external
// oracle: normal Go tests only need a candidate binary, while parity runs may
// supply a second binary at invocation time.
package parity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const defaultTimeout = 10 * time.Second

// Case describes one invocation shared by both implementations. Args, stdin,
// and the explicit environment overrides are passed unchanged to both
// processes.
type Case struct {
	Name  string
	Args  []string
	Stdin []byte
	Env   []string

	// CaptureFiles contains paths relative to the private working directory.
	// Missing files are recorded as absent; existing files are captured exactly.
	CaptureFiles []string

	// Timeout bounds process startup and execution. Zero uses the harness
	// default. A negative value is rejected.
	Timeout time.Duration

	// SemanticCompare opts this case out of normalized stdout/stderr equality.
	// Exit status and captured files are still compared, then this callback can
	// assert semantic fields such as JSON values or server observations.
	SemanticCompare func(goResult, rustResult Result) []Difference
}

// Runner executes binaries with one shared environment snapshot.
type Runner struct {
	Environment []string
}

// NewRunner returns a runner whose environment is a snapshot of the current
// process environment. Both binaries receive the same snapshot.
func NewRunner() Runner {
	return Runner{Environment: append([]string(nil), os.Environ()...)}
}

// Result contains process output and requested generated files.
type Result struct {
	ExitCode int
	TimedOut bool
	Stdout   []byte
	Stderr   []byte
	Files    map[string]File

	// WorkingDir is retained so callers can include it in diagnostics. It is
	// private to the result and should be removed with Cleanup after comparison.
	WorkingDir string
}

// File is one captured generated file.
type File struct {
	Present bool
	Data    []byte
}

// Cleanup removes the private working directory used by a result.
func (r Result) Cleanup() error {
	if r.WorkingDir == "" {
		return nil
	}
	return os.RemoveAll(r.WorkingDir)
}

// Run invokes binary for c. A non-zero exit status is part of the result and
// is not returned as an infrastructure error.
func (r Runner) Run(ctx context.Context, binary string, c Case) (Result, error) {
	if err := validateCase(binary, c); err != nil {
		return Result{}, err
	}

	workDir, err := os.MkdirTemp("", "fetch-parity-")
	if err != nil {
		return Result{}, fmt.Errorf("create parity working directory: %w", err)
	}
	return r.run(ctx, resolveBinary(binary), c, workDir, workDir)
}

func validateCase(binary string, c Case) error {
	if binary == "" {
		return errors.New("parity binary path is empty")
	}
	if c.Args == nil {
		return errors.New("parity case has no argument list")
	}
	if c.Timeout < 0 {
		return fmt.Errorf("parity case %q has a negative timeout", c.Name)
	}
	for _, path := range c.CaptureFiles {
		if err := validateRelativePath(path); err != nil {
			return fmt.Errorf("parity case %q: %w", c.Name, err)
		}
	}
	return nil
}

func (r Runner) run(ctx context.Context, binary string, c Case, workDir, stateDir string) (Result, error) {
	result := Result{WorkingDir: workDir}

	runCtx := ctx
	cancel := func() {}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	cmd := exec.CommandContext(runCtx, binary, c.Args...)
	cmd.Dir = workDir
	cmd.Env = mergeEnvironment(r.Environment, c.Env)
	// Keep config, cache, and home-relative state out of the developer's
	// environment. Compare resets this same directory between processes so
	// both binaries receive identical environment values without inheriting
	// one another's persistent state.
	cmd.Env = mergeEnvironment(cmd.Env, []string{
		"HOME=" + stateDir,
		"USERPROFILE=" + stateDir,
		"TMPDIR=" + stateDir,
		"TMP=" + stateDir,
		"TEMP=" + stateDir,
		"XDG_CONFIG_HOME=" + filepath.Join(stateDir, "config"),
		"XDG_CACHE_HOME=" + filepath.Join(stateDir, "cache"),
		"APPDATA=" + filepath.Join(stateDir, "config"),
		"FETCH_INTERNAL_SESSIONS_DIR=" + filepath.Join(stateDir, "sessions"),
	})
	cmd.Stdin = bytes.NewReader(c.Stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result.Stdout = append([]byte(nil), stdout.Bytes()...)
	result.Stderr = append([]byte(nil), stderr.Bytes()...)
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	} else {
		result.ExitCode = -1
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		result.TimedOut = true
		result.ExitCode = -1
	}
	if err != nil && result.ExitCode == -1 && !result.TimedOut {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			_ = result.Cleanup()
			result.WorkingDir = ""
			return Result{}, fmt.Errorf("run %q: %w", binary, err)
		}
	}

	result.Files = make(map[string]File, len(c.CaptureFiles))
	for _, path := range c.CaptureFiles {
		data, readErr := os.ReadFile(filepath.Join(workDir, filepath.FromSlash(path)))
		if errors.Is(readErr, os.ErrNotExist) {
			result.Files[path] = File{}
			continue
		}
		if readErr != nil {
			_ = result.Cleanup()
			result.WorkingDir = ""
			return Result{}, fmt.Errorf("capture %q from %q: %w", path, binary, readErr)
		}
		result.Files[path] = File{Present: true, Data: append([]byte(nil), data...)}
	}
	return result, nil
}

func resolveBinary(binary string) string {
	if filepath.IsAbs(binary) || !strings.ContainsAny(binary, `/\\`) {
		return binary
	}
	absolute, err := filepath.Abs(binary)
	if err != nil {
		return binary
	}
	return absolute
}

func validateRelativePath(path string) error {
	if path == "" {
		return errors.New("captured file path is empty")
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("captured file path %q must stay relative to the case directory", path)
	}
	return nil
}

func mergeEnvironment(base, overrides []string) []string {
	values := make(map[string]string, len(base)+len(overrides))
	order := make([]string, 0, len(base)+len(overrides))
	for _, entry := range append(append([]string(nil), base...), overrides...) {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			continue
		}
		if _, exists := values[key]; !exists {
			order = append(order, key)
		}
		values[key] = value
	}
	sort.Strings(order)
	env := make([]string, 0, len(order))
	for _, key := range order {
		env = append(env, key+"="+values[key])
	}
	return env
}

// Options controls nondeterminism normalization. The defaults match the
// migration contract and intentionally do not normalize arbitrary output.
type Options struct {
	Timing         bool
	DNSIDs         bool
	EphemeralPorts bool
	TemporaryPaths bool
	BuildVersions  bool
	Dates          bool
	HeaderOrder    bool
}

// DefaultOptions returns the documented parity normalizations.
func DefaultOptions() Options {
	return Options{
		Timing:         true,
		DNSIDs:         true,
		EphemeralPorts: true,
		TemporaryPaths: true,
		BuildVersions:  true,
		Dates:          true,
		HeaderOrder:    true,
	}
}

// Difference is one concise field-level parity mismatch.
type Difference struct {
	Field string
	Go    string
	Rust  string
}

// ComparisonError reports all mismatching fields rather than presenting only
// one large output diff.
type ComparisonError struct {
	Case        string
	Differences []Difference
}

func (e *ComparisonError) Error() string {
	var b strings.Builder
	if e.Case != "" {
		fmt.Fprintf(&b, "parity case %q failed:", e.Case)
	} else {
		b.WriteString("parity comparison failed:")
	}
	for _, difference := range e.Differences {
		fmt.Fprintf(&b, "\n- %s: Go=%s; Rust=%s", difference.Field, quote(difference.Go), quote(difference.Rust))
	}
	return b.String()
}

// Compare runs one case against the supplied Go and Rust/reference binaries.
func (r Runner) Compare(ctx context.Context, goBinary, rustBinary string, c Case, options Options) error {
	if err := validateCase(goBinary, c); err != nil {
		return err
	}
	if err := validateCase(rustBinary, c); err != nil {
		return err
	}
	stateDir, err := os.MkdirTemp("", "fetch-parity-state-")
	if err != nil {
		return fmt.Errorf("create parity state directory: %w", err)
	}
	defer os.RemoveAll(stateDir)

	goWorkDir, err := os.MkdirTemp("", "fetch-parity-go-")
	if err != nil {
		return fmt.Errorf("create Go parity working directory: %w", err)
	}
	goResult, err := r.run(ctx, resolveBinary(goBinary), c, goWorkDir, stateDir)
	if err != nil {
		return err
	}
	if err := resetDirectory(stateDir); err != nil {
		_ = goResult.Cleanup()
		return fmt.Errorf("reset parity state directory: %w", err)
	}

	rustWorkDir, err := os.MkdirTemp("", "fetch-parity-rust-")
	if err != nil {
		_ = goResult.Cleanup()
		return fmt.Errorf("create Rust parity working directory: %w", err)
	}
	rustResult, err := r.run(ctx, resolveBinary(rustBinary), c, rustWorkDir, stateDir)
	if err != nil {
		_ = goResult.Cleanup()
		return err
	}
	defer goResult.Cleanup()
	defer rustResult.Cleanup()
	return CompareResults(c, goResult, rustResult, options)
}

func resetDirectory(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(path, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

// CompareResults compares already captured results. It is useful for unit
// tests of normalization and for fixtures that record server-side semantics.
func CompareResults(c Case, goResult, rustResult Result, options Options) error {
	differences := make([]Difference, 0)
	if goResult.ExitCode != rustResult.ExitCode {
		differences = append(differences, Difference{"exit_code", fmt.Sprint(goResult.ExitCode), fmt.Sprint(rustResult.ExitCode)})
	}
	if goResult.TimedOut != rustResult.TimedOut {
		differences = append(differences, Difference{"timed_out", fmt.Sprint(goResult.TimedOut), fmt.Sprint(rustResult.TimedOut)})
	}
	if c.SemanticCompare == nil {
		goStdout := normalizeText(string(goResult.Stdout), goResult.WorkingDir, options)
		rustStdout := normalizeText(string(rustResult.Stdout), rustResult.WorkingDir, options)
		if goStdout != rustStdout {
			differences = append(differences, Difference{"stdout", goStdout, rustStdout})
		}
		goStderr := normalizeText(string(goResult.Stderr), goResult.WorkingDir, options)
		rustStderr := normalizeText(string(rustResult.Stderr), rustResult.WorkingDir, options)
		if goStderr != rustStderr {
			differences = append(differences, Difference{"stderr", goStderr, rustStderr})
		}
	}

	paths := make(map[string]struct{}, len(goResult.Files)+len(rustResult.Files))
	for path := range goResult.Files {
		paths[path] = struct{}{}
	}
	for path := range rustResult.Files {
		paths[path] = struct{}{}
	}
	orderedPaths := make([]string, 0, len(paths))
	for path := range paths {
		orderedPaths = append(orderedPaths, path)
	}
	sort.Strings(orderedPaths)
	for _, path := range orderedPaths {
		goFile, goOK := goResult.Files[path]
		rustFile, rustOK := rustResult.Files[path]
		if !goOK || !rustOK || goFile.Present != rustFile.Present {
			differences = append(differences, Difference{"file:" + path + ":present", fmt.Sprint(goFile.Present), fmt.Sprint(rustFile.Present)})
			continue
		}
		if goFile.Present {
			goData := normalizeFile(goFile.Data, goResult.WorkingDir, options)
			rustData := normalizeFile(rustFile.Data, rustResult.WorkingDir, options)
			if !bytes.Equal(goData, rustData) {
				differences = append(differences, Difference{"file:" + path, string(goData), string(rustData)})
			}
		}
	}
	if c.SemanticCompare != nil {
		differences = append(differences, c.SemanticCompare(goResult, rustResult)...)
	}
	if len(differences) != 0 {
		return &ComparisonError{Case: c.Name, Differences: differences}
	}
	return nil
}

var (
	timingValue      = `[-+]?(?:\d+(?:\.\d+)?)(?:\s*(?:ns|us|µs|ms|s))`
	timingPattern    = regexp.MustCompile(`(?i)((?:"|\b)(?:dns|tcp|connect|tls|quic|ttfb|wait|receive|transfer|duration|elapsed|timing|total)(?:"|\b)\s*[:=]\s*)` + timingValue)
	phaseTiming      = regexp.MustCompile(`(?i)((?:dns|tcp|tls|quic|ttfb|body|total)\b[^\r\n()]*\(\s*)` + timingValue + `(\s*\))`)
	waterfallTiming  = regexp.MustCompile(`(?im)^((?:\s*\*?\s*)(?:dns|tcp|tls|quic|ttfb|body|total)\b[^\r\n]*?)(` + timingValue + `)(\s*(?:\r?\n|$))`)
	dnsIDPattern     = regexp.MustCompile(`(?i)((?:dns\s*(?:transaction\s*)?id|transaction\s+id)\s*[:=]\s*)(?:0x)?[0-9a-f]+\b`)
	portPattern      = regexp.MustCompile(`(?i)((?:https?|wss?|quic)://(?:localhost|127\.0\.0\.1|\[::1\]|::1):)\d{1,5}`)
	datePattern      = regexp.MustCompile(`(?i)(?:\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})\b|\b(?:mon|tue|wed|thu|fri|sat|sun), \d{2} (?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec) \d{4} \d{2}:\d{2}:\d{2} GMT\b|\b\d{4}-\d{2}-\d{2}\b)`)
	versionPattern   = regexp.MustCompile(`(?i)(?:go1\.\d+(?:\.\d+)?|rustc\s+\d+\.\d+\.\d+|fetch\s+(?:\(devel\)|v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?))`)
	headerPattern    = regexp.MustCompile(`^(?:[<>] ?)?([!#$%&'*+\-.^_` + "|" + `~0-9A-Za-z]+):[ \t].*$`)
	httpStartPattern = regexp.MustCompile(`^(?:[<>] ?)?(?:HTTP/\d(?:\.\d+)?\s+\d{3}|[A-Z]+(?:\s+.*)?\s+HTTP/\d(?:\.\d+)?)`)
)

func normalizeText(value, workDir string, options Options) string {
	if options.TemporaryPaths && workDir != "" {
		value = strings.ReplaceAll(value, workDir, "<workdir>")
		value = strings.ReplaceAll(value, filepath.ToSlash(workDir), "<workdir>")
	}
	if options.Timing {
		value = timingPattern.ReplaceAllString(value, `${1}<timing>`)
		value = phaseTiming.ReplaceAllString(value, `${1}<timing>${2}`)
		value = waterfallTiming.ReplaceAllString(value, `${1}<timing>${3}`)
	}
	if options.DNSIDs {
		value = dnsIDPattern.ReplaceAllString(value, `${1}<dns-id>`)
	}
	if options.EphemeralPorts {
		value = portPattern.ReplaceAllString(value, `${1}<port>`)
	}
	if options.Dates {
		value = datePattern.ReplaceAllString(value, `<date>`)
	}
	if options.BuildVersions {
		value = versionPattern.ReplaceAllString(value, `<build-version>`)
	}
	if options.HeaderOrder {
		value = normalizeHeaderBlocks(value)
	}
	return value
}

func normalizeFile(data []byte, workDir string, options Options) []byte {
	if !utf8.Valid(data) {
		return data
	}
	return []byte(normalizeText(string(data), workDir, options))
}

func normalizeHeaderBlocks(value string) string {
	lines := strings.SplitAfter(value, "\n")
	for i := 0; i < len(lines); {
		if !headerPattern.MatchString(strings.TrimSuffix(lines[i], "\n")) || !isHTTPHeaderBlockStart(lines, i) {
			i++
			continue
		}
		prefix := headerPrefix(lines[i])
		end := i
		for end < len(lines) && headerPattern.MatchString(strings.TrimSuffix(lines[end], "\n")) && headerPrefix(lines[end]) == prefix {
			end++
		}
		if end-i > 0 {
			canonical := canonicalHeaderBlock(lines[i:end])
			updated := make([]string, 0, len(lines)-(end-i)+len(canonical))
			updated = append(updated, lines[:i]...)
			updated = append(updated, canonical...)
			updated = append(updated, lines[end:]...)
			lines = updated
			end = i + len(canonical)
		}
		i = end
	}
	return strings.Join(lines, "")
}

func isHTTPHeaderBlockStart(lines []string, index int) bool {
	if index == 0 {
		return false
	}
	previous := strings.TrimSuffix(lines[index-1], "\n")
	return httpStartPattern.MatchString(previous)
}

func canonicalHeaderBlock(lines []string) []string {
	// Sort complete lines only. Do not split comma-separated values or trim
	// them: duplicate occurrences and value bytes are part of parity, and
	// Set-Cookie is not safely comma-combinable.
	canonical := append([]string(nil), lines...)
	sort.SliceStable(canonical, func(left, right int) bool {
		return strings.ToLower(headerName(canonical[left])) < strings.ToLower(headerName(canonical[right]))
	})
	return canonical
}

func headerPrefix(line string) string {
	line = strings.TrimSuffix(line, "\n")
	if strings.HasPrefix(line, "> ") || strings.HasPrefix(line, "< ") {
		return line[:2]
	}
	if strings.HasPrefix(line, ">") || strings.HasPrefix(line, "<") {
		return line[:1]
	}
	return ""
}

func headerName(line string) string {
	line = strings.TrimSuffix(line, "\n")
	start := len(headerPrefix(line))
	colon := strings.IndexByte(line[start:], ':')
	if colon < 0 {
		return line[start:]
	}
	colon += start
	return strings.TrimSpace(line[start:colon])
}

func quote(value string) string {
	if value == "" {
		return `""`
	}
	if len(value) > 512 {
		value = value[:512] + "…"
	}
	return fmt.Sprintf("%q", value)
}
