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
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}

	err = os.Rename(f.Name(), filename)
	return err

}

func getOutputValue(r *Request, hdrs http.Header) (string, error) {
	if r.Output != "" {
		// Output was provided directly.
		return r.Output, nil
	}
	if !r.OutputDir {
		// Remote output option wasn't provided, return an empty string.
		return "", nil
	}

	// Attempt to get filename from the Content-Disposition header first.
	cdName := getContentDispositionFilename(hdrs)
	if cdName != "" {
		return cdName, nil
	}

	// Get the final path component as the file name.
	path := r.URL.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	for path != "" {
		var after string
		path, after, _ = cutLast(path, "/")
		if after != "" {
			return after, nil
		}

	}

	// Fallback to the hostname as the file path and emit a warning.
	host := r.URL.Hostname()
	if host != "" {
		return host, nil
	}

	return "", errNoInferFilePath{}
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
