package config

import (
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

// File represents a configuration file.
type File struct {
	Global *Config
	Hosts  map[string]*Config
}

// GetFile returns a config File, or nil if one cannot be found.
func GetFile(path string) (*File, error) {
	path, buf, err := getConfigFile(path)
	if err != nil || path == "" {
		return nil, err
	}
	return parseFile(path, string(buf))
}

// getConfigFile searches for a local config file, returning the file contents
// if it exists.
func getConfigFile(path string) (string, []byte, error) {
	if path != "" {
		// Expand '~' to the home directory.
		if len(path) >= 2 && path[0] == '~' && path[1] == os.PathSeparator {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", nil, err
			}
			path = home + path[1:]
		}
		// Direct config path was provided.
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", nil, err
		}
		return readFile(abs)
	}

	if runtime.GOOS == "windows" {
		appData := os.Getenv("AppData")
		if appData == "" {
			return "", nil, nil
		}
		path, buf, err := readFile(filepath.Join(appData, "fetch", "config"))
		if err != nil {
			return "", nil, nil
		}
		return path, buf, nil
	}

	xdgHome := os.Getenv("XDG_CONFIG_HOME")
	if xdgHome != "" {
		path, buf, err := readFile(xdgHome + "/fetch/config")
		if err == nil {
			return path, buf, nil
		}
	}

	home := os.Getenv("HOME")
	if home != "" {
		path, buf, err := readFile(home + "/.config/fetch/config")
		if err == nil {
			return path, buf, nil
		}
	}

	return "", nil, nil
}

func readFile(path string) (string, []byte, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	return path, buf, nil
}

// parseFile parses the provided File, returning any error encountered.
func parseFile(path, s string) (*File, error) {
	f := File{Global: &Config{isFile: true}}

	config := f.Global
	for num, line := range lines(s) {
		line = strings.TrimSpace(line)

		if line == "" || line[0] == '#' {
			// Skip empty lines and comments.
			continue
		}

		// Parse out a hostname.
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			hostStr := strings.TrimSpace(line[1 : len(line)-1])
			if hostStr == "" {
				return nil, newFileError(path, num, errors.New("hostname cannot be empty"))
			}

			config = &Config{isFile: true}
			if f.Hosts == nil {
				f.Hosts = make(map[string]*Config)
			}
			f.Hosts[hostStr] = config
			continue
		}

		// Pares a key and value pair.
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, newFileError(path, num, fmt.Errorf("invalid key/value pair '%s'", line))
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)

		err := config.Set(key, val)
		if err != nil {
			return nil, newFileError(path, num, err)
		}
	}

	return &f, nil
}

// lines returns an iterator over lines and line numbers.
func lines(s string) iter.Seq2[int, string] {
	return func(yield func(int, string) bool) {
		var num int
		for len(s) > 0 {
			num++

			i := strings.IndexFunc(s, func(r rune) bool {
				return r == '\n' || r == '\r'
			})
			if i < 0 {
				yield(num, s)
				return
			}

			if !yield(num, s[:i]) {
				return
			}

			n := 1
			if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				n = 2
			}
			s = s[i+n:]
		}
	}
}

// fileError represents an error that prints a config file line with an err.
type fileError struct {
	file string
	line int
	err  error
}

func newFileError(file string, line int, err error) fileError {
	return fileError{file: file, line: line, err: err}
}

func (err fileError) Error() string {
	return fmt.Sprintf("config file '%s': line %d: %s", err.file, err.line, err.err.Error())
}

func (err fileError) PrintTo(p *core.Printer) {
	p.WriteString("config file '")
	p.Set(core.Dim)
	p.WriteString(err.file)
	p.Reset()
	p.WriteString("': line ")
	p.WriteString(strconv.Itoa(err.line))
	p.WriteString(": ")

	if pt, ok := err.err.(core.PrinterTo); ok {
		pt.PrintTo(p)
	} else {
		p.WriteString(err.err.Error())
	}
}
