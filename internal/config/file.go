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
	Path   string
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
			path = filepath.Join(home, path[2:])
		}

		// An explicit path is authoritative. Do not turn a missing file into a
		// silent "no config" result, and report the normalized path so callers
		// can identify the file that was requested.
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", nil, err
		}
		buf, err := os.ReadFile(abs)
		if err != nil {
			if os.IsNotExist(err) {
				return "", nil, core.FileNotExistsError(abs)
			}
			return "", nil, err
		}
		return abs, buf, nil
	}

	for _, candidate := range configSearchPaths(runtime.GOOS, os.Getenv) {
		path, buf, err := readFile(candidate)
		if err == nil {
			return path, buf, nil
		}
	}
	return "", nil, nil
}

// configSearchPaths returns candidates in precedence order. Keep this small
// and injectable so Windows path precedence can be tested on every platform.
func configSearchPaths(goos string, getenv func(string) string) []string {
	var paths []string
	add := func(path string) {
		if path == "" {
			return
		}
		for _, existing := range paths {
			if existing == path {
				return
			}
		}
		paths = append(paths, path)
	}

	if xdgHome := getenv("XDG_CONFIG_HOME"); xdgHome != "" {
		add(filepath.Join(xdgHome, "fetch", "config"))
	}

	home := getenv("HOME")
	if home == "" && goos == "windows" {
		home = getenv("USERPROFILE")
	}
	if home != "" {
		add(filepath.Join(home, ".config", "fetch", "config"))
	}

	if goos == "windows" {
		if appData := getenv("AppData"); appData != "" {
			add(filepath.Join(appData, "fetch", "config"))
		}
	}
	return paths
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
	f := File{Global: &Config{isFile: true}, Path: path}
	hostLines := make(map[string]int)

	config := f.Global
	for num, rawLine := range lines(s) {
		line := strings.TrimSpace(rawLine)

		if line == "" || line[0] == '#' {
			// Skip empty lines and comments.
			continue
		}

		// Parse out a hostname.
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			hostStr := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if hostStr == "" {
				return nil, newFileError(path, num, errors.New("hostname cannot be empty"))
			}

			if strings.Contains(hostStr, "*") {
				if !strings.HasPrefix(hostStr, "*.") || len(hostStr) < 3 || strings.Contains(hostStr[2:], "*") {
					err := fmt.Errorf("invalid wildcard hostname '%s': must be in the format '*.domain'", hostStr)
					return nil, newFileError(path, num, err)
				}
			}

			if previousLine, exists := hostLines[hostStr]; exists {
				err := fmt.Errorf("duplicate host section '%s' (lines %d and %d)", hostStr, previousLine, num)
				return nil, newFileError(path, num, err)
			}
			hostLines[hostStr] = num

			config = &Config{isFile: true}
			if f.Hosts == nil {
				f.Hosts = make(map[string]*Config)
			}
			f.Hosts[hostStr] = config
			continue
		}

		// Parse a key and value pair. Keep value whitespace for headers and
		// queries; other config values retain their historical trimming.
		key, val, ok := strings.Cut(strings.TrimLeft(rawLine, " \t"), "=")
		if !ok {
			return nil, newFileError(path, num, fmt.Errorf("invalid key/value pair '%s'", line))
		}
		key = strings.TrimSpace(key)
		val = strings.TrimLeft(val, " \t")
		if key != "header" && key != "query" {
			val = strings.TrimSpace(val)
		}

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

// HostConfig returns the Config for the given hostname, using exact match
// first, then falling back to the most-specific wildcard match.
func (f *File) HostConfig(hostname string) *Config {
	if hostname == "" {
		return nil
	}
	hostname = strings.ToLower(hostname)

	// Exact match first.
	if cfg, ok := f.Hosts[hostname]; ok {
		return cfg
	}

	// Wildcard: find longest (most specific) suffix match.
	var best *Config
	var bestLen int
	for key, cfg := range f.Hosts {
		if !strings.HasPrefix(key, "*.") {
			continue
		}
		suffix := key[1:] // e.g. ".example.com"
		if strings.HasSuffix(hostname, suffix) && len(suffix) > bestLen {
			bestLen = len(suffix)
			best = cfg
		}
	}
	return best
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
