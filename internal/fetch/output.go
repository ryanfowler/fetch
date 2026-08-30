package fetch

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/fileutil"
)

func writeOutputToFile(filename string, body io.Reader, size int64, p *core.Printer, v core.Verbosity, clobber bool) (err error) {
	name, err := filepath.Abs(filename)
	if err != nil {
		return err
	}
	if err = checkOutputFile(name, clobber); err != nil {
		return err
	}

	dir := filepath.Dir(name)
	// Keep the temporary name independent of the server/user filename. This
	// avoids exceeding filesystem component limits for a 255-byte destination.
	f, err := os.CreateTemp(dir, ".fetch-download-*")
	if err != nil {
		return err
	}
	tempName := f.Name()
	defer func() {
		if tempName != "" {
			_ = os.Remove(tempName)
		}
	}()

	// Optionally show a progress bar/spinner on stderr.
	if v > core.VSilent {
		if core.IsStderrTerm {
			if size > 0 {
				pb := newProgressBar(body, p, size)
				defer func() { pb.Close(name, err) }()
				body = pb
			} else {
				ps := newProgressSpinner(body, p)
				defer func() { ps.Close(name, err) }()
				body = ps
			}
		} else {
			ps := newProgressStatic(body, p)
			defer func() { ps.Close(name, err) }()
			body = ps
		}
	}

	if _, err = io.Copy(f, body); err != nil {
		_ = f.Close()
		return err
	}
	// Sync the payload before making it visible. Some filesystems and Windows
	// filesystems do not support this operation, so durability is best effort.
	_ = f.Sync()
	if err = f.Close(); err != nil {
		return err
	}

	// Recheck immediately before commit. This catches a symlink or directory
	// that appeared after the response was received, while the atomic install
	// helpers handle a destination race without exposing a partial file.
	if err = checkOutputFile(name, clobber); err != nil {
		return err
	}
	if clobber {
		err = fileutil.AtomicReplaceFileNoSymlinkPreserveMode(tempName, name)
	} else {
		err = fileutil.AtomicWriteNewFile(tempName, name)
	}
	if err != nil {
		var committed *fileutil.CommittedError
		if errors.As(err, &committed) {
			// The destination is installed. Keep tempName set so the deferred
			// cleanup gets one more chance to remove the hard link.
			err = nil
			_ = fileutil.SyncDir(dir)
			return nil
		}
		if errors.Is(err, fileutil.ErrSymlinkTarget) {
			return errOutputSymlink{path: name}
		}
		if !clobber && errors.Is(err, os.ErrExist) {
			return errFileExists{path: name}
		}
		return err
	}
	tempName = ""
	_ = fileutil.SyncDir(dir)
	return nil
}

func getOutputValue(r *Request, resp *http.Response) (string, error) {
	name, _, err := getOutputValueDetails(r, resp)
	return name, err
}

func getOutputValueDetails(r *Request, resp *http.Response) (string, string, error) {
	if r.Output != "" {
		// Output was provided directly via -o. User-supplied paths are not
		// sanitized, but they still receive the same destination checks.
		if r.Output != "-" {
			if err := checkOutputFile(r.Output, r.Clobber); err != nil {
				return "", "", err
			}
		}
		return r.Output, "", nil
	}
	if !r.RemoteName {
		return "", "", nil
	}

	var filename string
	var warning string

	if r.RemoteHeaderName {
		var headers http.Header
		if resp != nil {
			headers = resp.Header
		}
		cdName, valid := getContentDispositionFilenameDetails(headers)
		if valid {
			filename, _ = sanitizeFilename(cdName)
		}
		if filename == "" {
			warning = "unable to use the Content-Disposition filename; falling back to the URL filename"
		}
	}

	requestURL := (*url.URL)(nil)
	if resp != nil && resp.Request != nil {
		requestURL = resp.Request.URL
	}
	if filename == "" && requestURL != nil {
		path := requestURL.Path
		for path != "" {
			var after string
			if before, _, found := cutLast(path, "/"); found {
				path, after = before, path[len(before)+1:]
			} else {
				after, path = path, ""
			}
			if after != "" {
				if sanitized, err := sanitizeFilename(after); err == nil {
					filename = sanitized
					break
				}
			}
		}
	}

	if filename == "" && requestURL != nil {
		if host := requestURL.Hostname(); host != "" {
			filename, _ = sanitizeFilename(host)
		}
	}
	if filename == "" {
		return "", warning, errNoInferFilePath{}
	}

	if err := checkOutputFile(filename, r.Clobber); err != nil {
		return "", warning, err
	}
	return filename, warning, nil
}

func checkOutputFile(filename string, clobber bool) error {
	info, err := os.Lstat(filename)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errOutputSymlink{path: filename}
		}
		if !info.Mode().IsRegular() {
			return errFileCheck{path: filename, err: errors.New("output path is not a regular file")}
		}
		if !clobber {
			return errFileExists{path: filename}
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return errFileCheck{path: filename, err: err}
	}
	if _, err := os.Stat(filepath.Dir(filename)); err != nil {
		return errFileCheck{path: filename, err: err}
	}
	return nil
}

const maxOutputFilenameBytes = 255

func sanitizeFilename(filename string) (string, error) {
	// Treat both separators as path separators even on Unix. Content-Disposition
	// is supplied by a remote server and must never choose a nested path.
	filename = strings.TrimRight(filename, "/\\")
	if idx := strings.LastIndexAny(filename, "/\\"); idx >= 0 {
		filename = filename[idx+1:]
	}
	if filename == "" {
		return "", errInvalidFilename{filename: filename}
	}

	var b strings.Builder
	for _, r := range filename {
		switch {
		case r == 0 || r < 0x20 || (r >= 0x7f && r <= 0x9f) || unicode.IsControl(r):
			b.WriteByte('_')
		case strings.ContainsRune(`<>:"/\|?*`, r):
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	filename = strings.TrimRight(b.String(), " .")
	if filename == "" || filename == "." || filename == ".." {
		return "", errInvalidFilename{filename: filename}
	}
	for len(filename) > maxOutputFilenameBytes {
		filename = filename[:len(filename)-1]
		for !utf8.ValidString(filename) {
			filename = filename[:len(filename)-1]
		}
	}
	if filename == "" {
		return "", errInvalidFilename{filename: filename}
	}

	// Reject Windows device names on every platform so downloads behave the
	// same way when moved between operating systems.
	stem := filename
	if dot := strings.IndexByte(stem, '.'); dot >= 0 {
		stem = stem[:dot]
	}
	stem = strings.TrimRight(stem, " .")
	upper := strings.ToUpper(stem)
	if upper == "CON" || upper == "CONIN$" || upper == "CONOUT$" || upper == "PRN" || upper == "AUX" || upper == "NUL" ||
		(len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) && upper[3] >= '1' && upper[3] <= '9') {
		return "", errInvalidFilename{filename: filename}
	}
	return filename, nil
}

func getContentDispositionFilenameDetails(hdrs http.Header) (string, bool) {
	cd := hdrs.Get("Content-Disposition")
	if cd == "" {
		return "", false
	}
	parts := splitHeaderParameters(cd)
	if len(parts) < 2 {
		return "", false
	}

	var plain, extended string
	for _, part := range parts[1:] {
		key, value, ok := parseHeaderParameter(part)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "filename*":
			if decoded, ok := decodeExtendedFilename(value); ok && extended == "" {
				extended = decoded
			}
		case "filename":
			if plain == "" {
				plain = value
			}
		}
	}
	if extended != "" {
		// Prefer filename* when it is usable as a local filename. If it
		// decodes to a reserved or otherwise invalid name, continue with the
		// plain filename parameter before falling back to the URL.
		if _, err := sanitizeFilename(extended); err == nil {
			return extended, true
		}
	}
	if plain != "" {
		return plain, true
	}
	if extended != "" {
		return extended, true
	}
	return "", false
}

func splitHeaderParameters(value string) []string {
	var parts []string
	start := 0
	quoted, escaped := false, false
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\\':
			if quoted {
				escaped = !escaped
			}
		case '"':
			if !escaped {
				quoted = !quoted
			}
			escaped = false
		case ';':
			if !quoted {
				parts = append(parts, value[start:i])
				start = i + 1
			}
		default:
			escaped = false
		}
	}
	parts = append(parts, value[start:])
	return parts
}

func parseHeaderParameter(part string) (string, string, bool) {
	idx := strings.IndexByte(part, '=')
	if idx < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(part[:idx])
	if key == "" {
		return "", "", false
	}
	value := strings.TrimSpace(part[idx+1:])
	if len(value) >= 2 && value[0] == '"' {
		if value[len(value)-1] != '"' {
			return "", "", false
		}
		var b strings.Builder
		escaped := false
		for _, r := range value[1 : len(value)-1] {
			if escaped {
				b.WriteRune(r)
				escaped = false
			} else if r == '\\' {
				escaped = true
			} else if r == '"' || r == '\r' || r == '\n' {
				return "", "", false
			} else {
				b.WriteRune(r)
			}
		}
		if escaped {
			return "", "", false
		}
		return key, b.String(), true
	}
	if strings.ContainsAny(value, "\\\"\r\n") {
		return "", "", false
	}
	return key, value, value != ""
}

func decodeExtendedFilename(value string) (string, bool) {
	first := strings.IndexByte(value, '\'')
	if first <= 0 {
		return "", false
	}
	rest := value[first+1:]
	second := strings.IndexByte(rest, '\'')
	if second < 0 {
		return "", false
	}
	charset := strings.ToLower(value[:first])
	encoded := rest[second+1:]
	decoded, err := url.PathUnescape(encoded)
	if err != nil {
		return "", false
	}
	switch charset {
	case "utf-8", "utf8":
		if !utf8.ValidString(decoded) {
			return "", false
		}
	case "iso-8859-1", "latin1":
		var b strings.Builder
		for i := 0; i < len(decoded); i++ {
			b.WriteRune(rune(decoded[i]))
		}
		decoded = b.String()
	default:
		return "", false
	}
	return decoded, decoded != ""
}

func cutLast(s, sep string) (string, string, bool) {
	idx := strings.LastIndex(s, sep)
	if idx < 0 {
		return s, "", false
	}
	return s[:idx], s[idx+1:], true
}

type errNoInferFilePath struct{}

func (err errNoInferFilePath) Error() string {
	return "unable to infer a file name for the output\n\nTo specify an exact path, try '--output <PATH>'"
}

func (err errNoInferFilePath) PrintTo(p *core.Printer) {
	p.WriteString("unable to infer a file name for the output\n\n")

	p.WriteString("To specify an exact path, try '")
	p.Set(core.Bold)
	p.WriteString("--output")
	p.Reset()
	p.WriteString(" <PATH>")
	p.WriteString("'")
}

type errInvalidFilename struct {
	filename string
}

func (err errInvalidFilename) Error() string {
	return "invalid filename: '" + err.filename + "'"
}

func (err errInvalidFilename) PrintTo(p *core.Printer) {
	p.WriteString("invalid filename: '")
	p.Set(core.Dim)
	p.WriteString(core.TerminalSafeText(err.filename))
	p.Reset()
	p.WriteString("'")
}

type errOutputSymlink struct {
	path string
}

func (err errOutputSymlink) Error() string {
	return "refusing to write through symlink output path '" + err.path + "'"
}

func (err errOutputSymlink) PrintTo(p *core.Printer) {
	p.WriteString("refusing to write through symlink output path '")
	p.Set(core.Dim)
	p.WriteString(core.TerminalSafeText(err.path))
	p.Reset()
	p.WriteString("'")
}

type errFileExists struct {
	path string
}

func (err errFileExists) Error() string {
	return "file '" + err.path + "' already exists\n\nTo overwrite existing files, try '--clobber'"
}

func (err errFileExists) PrintTo(p *core.Printer) {
	p.WriteString("file '")
	p.Set(core.Dim)
	p.WriteString(core.TerminalSafeText(err.path))
	p.Reset()
	p.WriteString("' already exists\n\n")

	p.WriteString("To overwrite existing files, try '")
	p.Set(core.Bold)
	p.WriteString("--clobber")
	p.Reset()
	p.WriteString("'")
}

type errFileCheck struct {
	path string
	err  error
}

func (err errFileCheck) Error() string {
	return "unable to check output file '" + err.path + "': " + err.err.Error()
}

func (err errFileCheck) Unwrap() error {
	return err.err
}

func (err errFileCheck) PrintTo(p *core.Printer) {
	p.WriteString("unable to check output file '")
	p.Set(core.Dim)
	p.WriteString(core.TerminalSafeText(err.path))
	p.Reset()
	p.WriteString("': ")
	p.WriteString(core.TerminalSafeText(err.err.Error()))
}
