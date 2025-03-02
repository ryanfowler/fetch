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
	buf, err := getConfigFile(path)
	if err != nil || buf == nil {
		return nil, err
	}
	return parseFile(string(buf))
}

// getConfigFile searches for a local config file, returning the file contents
// if it exists.
func getConfigFile(path string) ([]byte, error) {
	if path != "" {
		// Direct config path was provided.
		return os.ReadFile(path)
	}

	if runtime.GOOS == "windows" {
		appData := os.Getenv("AppData")
		if appData == "" {
			return nil, nil
		}
		d, err := os.ReadFile(filepath.Join(appData, "fetch", "config"))
		if err != nil {
			return nil, nil
		}
		return d, nil
	}

	xdgHome := os.Getenv("XDG_CONFIG_HOME")
	if xdgHome != "" {
		f, err := os.ReadFile(xdgHome + "/fetch/config")
		if err == nil {
			return f, nil
		}
	}

	home := os.Getenv("HOME")
	if home != "" {
		f, err := os.ReadFile(home + "/.config/fetch/config")
		if err == nil {
			return f, nil
		}
	}

	return nil, nil
}

// parseFile parses the provided File, returning any error encountered.
func parseFile(s string) (*File, error) {
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
				return nil, newFileError(num, errors.New("empty hostname"))
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
			return nil, newFileError(num, fmt.Errorf("invalid key/value pair: '%s'", line))
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)

		err := config.Set(key, val)
		if err != nil {
			return nil, fileLineError{line: num, err: err}
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

// fileLineError represents an error that prints a config file line with an err.
type fileLineError struct {
	line int
	err  error
}

func newFileError(line int, err error) fileLineError {
	return fileLineError{line: line, err: err}
}

func (err fileLineError) Error() string {
	return fmt.Sprintf("config file: line %d: %s", err.line, err.err.Error())
}

func (err fileLineError) PrintTo(p *core.Printer) {
	p.WriteString("config file: line ")
	p.Set(core.Bold)
	p.WriteString(strconv.Itoa(err.line))
	p.Reset()
	p.WriteString(": ")

	if pt, ok := err.err.(core.PrinterTo); ok {
		pt.PrintTo(p)
	} else {
		p.WriteString(err.err.Error())
	}
}
