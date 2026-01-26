package fetch

import (
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

func writeOutputToFile(filename string, body io.Reader, size int64, p *core.Printer, v core.Verbosity) error {
	name, err := filepath.Abs(filename)
	if err != nil {
		return err
	}

	dir := filepath.Dir(name)
	base := filepath.Base(name)
	f, err := os.CreateTemp(dir, base+".*.download")
	if err != nil {
		return err
	}

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
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err = f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}

	err = os.Rename(f.Name(), filename)
	return err

}

func getOutputValue(r *Request, resp *http.Response) (string, error) {
	if r.Output != "" {
		// Output was provided directly via -o, return it without sanitization.
		return r.Output, nil
	}
	if !r.RemoteName {
		// Remote output option (-O) wasn't provided, return an empty string.
		return "", nil
	}

	var filename string

	// If -J is set, try Content-Disposition header first.
	if r.RemoteHeaderName {
		if cdName := getContentDispositionFilename(resp.Header); cdName != "" {
			if sanitized, err := sanitizeFilename(cdName); err == nil {
				filename = sanitized
			}
		}
	}

	// Fall back to URL path component.
	if filename == "" {
		path := resp.Request.URL.Path
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		for path != "" {
			var after string
			path, after, _ = cutLast(path, "/")
			if after != "" {
				if sanitized, err := sanitizeFilename(after); err == nil {
					filename = sanitized
					break
				}
			}
		}
	}

	// Fallback to the hostname as the file path.
	if filename == "" {
		if host := resp.Request.URL.Hostname(); host != "" {
			filename = host
		}
	}

	if filename == "" {
		return "", errNoInferFilePath{}
	}

	// Check if file exists (unless --clobber is set).
	if !r.Clobber {
		_, err := os.Stat(filename)
		if err == nil {
			return "", errFileExists{path: filename}
		}
		if !os.IsNotExist(err) {
			return "", errFileCheck{path: filename, err: err}
		}
	}

	return filename, nil
}

func sanitizeFilename(filename string) (string, error) {
	base := filepath.Base(filename)
	if base == "" || base == "." || base == ".." {
		return "", errInvalidFilename{filename: filename}
	}
	return base, nil
}

func getContentDispositionFilename(hdrs http.Header) string {
	cd := hdrs.Get("Content-Disposition")
	if cd == "" {
		return ""
	}

	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return ""
	}

	return params["filename"]
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
	p.WriteString(err.filename)
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
	p.WriteString(err.path)
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
	p.WriteString(err.path)
	p.Reset()
	p.WriteString("': ")
	p.WriteString(err.err.Error())
}
