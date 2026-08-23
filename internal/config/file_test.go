package config

import (
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestParseFile(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		expFile *File
		expErr  string
	}{
		{
			name: "valid wildcard section",
			config: `[*.Example.com]
				insecure = true`,
			expFile: &File{
				Global: &Config{isFile: true},
				Hosts: map[string]*Config{
					"*.example.com": {
						isFile:   true,
						Insecure: new(true),
					},
				},
				Path: "test/config",
			},
		},
		{
			name:   "invalid wildcard missing dot",
			config: `[*example.com]`,
			expErr: "invalid wildcard hostname '*example.com': must be in the format '*.domain'",
		},
		{
			name:   "invalid wildcard only star dot",
			config: `[*.]`,
			expErr: "invalid wildcard hostname '*.': must be in the format '*.domain'",
		},
		{
			name:   "invalid wildcard double star",
			config: `[*.*.com]`,
			expErr: "invalid wildcard hostname '*.*.com': must be in the format '*.domain'",
		},
		{
			name:   "invalid wildcard star in middle",
			config: `[example.*.com]`,
			expErr: "invalid wildcard hostname 'example.*.com': must be in the format '*.domain'",
		},
		{
			name: "successful parse",
			config: `
				timeout = 10
				tls = 1.2
				max-tls = 1.3`,
			expFile: &File{
				Global: &Config{
					isFile:  true,
					Timeout: new(10 * time.Second),
					TLSMax:  new(uint16(tls.VersionTLS13)),
					TLSMin:  new(uint16(tls.VersionTLS12)),
				},
				Path: "test/config",
			},
		},
		{
			name: "successful parse with hosts",
			config: `
				# This is a comment
				color = off
				no-pager = true
				
				[Example.com]
				insecure = true

				[anotherhost.com]
				ignore-status = true`,
			expFile: &File{
				Global: &Config{
					isFile:  true,
					Color:   core.ColorOff,
					NoPager: new(true),
				},
				Hosts: map[string]*Config{
					"example.com": {
						isFile:   true,
						Insecure: new(true),
					},
					"anotherhost.com": {
						isFile:       true,
						IgnoreStatus: new(true),
					},
				},
				Path: "test/config",
			},
		},
		{
			name: "invalid key and value pair",
			config: `
				color = off
				invalidline`,
			expErr: "line 3: invalid key/value pair 'invalidline'",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, err := parseFile("test/config", test.config)
			if err != nil {
				if test.expErr == "" {
					t.Fatalf("unexpected error: %s", err.Error())
				}
				if !strings.Contains(err.Error(), test.expErr) {
					t.Fatalf("unexpected error: %s", err.Error())
				}
				return
			}

			if !reflect.DeepEqual(f, test.expFile) {
				t.Fatalf("unexpected file: %+v\n", *f)
			}
		})
	}
}

func TestParseFileRejectsDuplicateHostSectionsWithBothLines(t *testing.T) {
	_, err := parseFile("test/config", "[Example.com]\ncolor = off\n\n[example.COM]\ncolor = on\n")
	if err == nil {
		t.Fatal("expected duplicate host section error")
	}
	message := err.Error()
	for _, want := range []string{"duplicate host section 'example.com'", "lines 1 and 4", "line 4"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error = %q, want substring %q", message, want)
		}
	}
}

func TestGetConfigFileExplicitMissingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "fetch.conf")
	_, _, err := getConfigFile(path)
	if err == nil {
		t.Fatal("expected missing config error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error = %q, want path %q", err, path)
	}
}

func TestGetConfigFileSearchFallsThroughMissingCandidate(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "missing"))
	home := t.TempDir()
	t.Setenv("HOME", home)

	path := filepath.Join(home, ".config", "fetch", "config")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("color = off\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	gotPath, gotBuf, err := getConfigFile("")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != path {
		t.Fatalf("path = %q, want %q", gotPath, path)
	}
	if got := string(gotBuf); got != "color = off\n" {
		t.Fatalf("contents = %q, want %q", got, "color = off\n")
	}
}

func TestGetConfigFileSearchReturnsReadErrorWithoutFallingThrough(t *testing.T) {
	xdgHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdgHome)
	home := t.TempDir()
	t.Setenv("HOME", home)

	xdgPath := filepath.Join(xdgHome, "fetch", "config")
	if err := os.MkdirAll(xdgPath, 0o755); err != nil {
		t.Fatal(err)
	}
	homePath := filepath.Join(home, ".config", "fetch", "config")
	if err := os.MkdirAll(filepath.Dir(homePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(homePath, []byte("color = off\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	gotPath, gotBuf, err := getConfigFile("")
	if err == nil {
		t.Fatal("expected read error")
	}
	if gotPath != "" || gotBuf != nil {
		t.Fatalf("path, contents = %q, %q; want empty results", gotPath, gotBuf)
	}
	if !strings.Contains(err.Error(), xdgPath) {
		t.Fatalf("error = %q, want path %q", err, xdgPath)
	}
}

func TestConfigSearchPathsWindowsIncludesXDGAndHomeBeforeAppData(t *testing.T) {
	env := map[string]string{
		"XDG_CONFIG_HOME": "/xdg",
		"HOME":            "/home/user",
		"USERPROFILE":     `C:\\Users\\user`,
		"AppData":         `C:\\Users\\user\\AppData\\Roaming`,
	}
	paths := configSearchPaths("windows", func(name string) string { return env[name] })
	want := []string{
		filepath.Join("/xdg", "fetch", "config"),
		filepath.Join("/home/user", ".config", "fetch", "config"),
		filepath.Join(`C:\\Users\\user\\AppData\\Roaming`, "fetch", "config"),
	}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
}

func TestConfigSearchPathsDoesNotUseWindowsVariablesOnUnix(t *testing.T) {
	env := map[string]string{
		"USERPROFILE": `C:\\Users\\user`,
		"AppData":     `C:\\Users\\user\\AppData\\Roaming`,
	}
	if paths := configSearchPaths("linux", func(name string) string { return env[name] }); len(paths) != 0 {
		t.Fatalf("paths = %#v, want no paths", paths)
	}
}

func TestConfigSearchPathsSkipsUnsetAppData(t *testing.T) {
	env := map[string]string{"HOME": "/home/user"}
	paths := configSearchPaths("windows", func(name string) string { return env[name] })
	want := []string{filepath.Join("/home/user", ".config", "fetch", "config")}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
}

func TestMergePreservesListOrderAcrossScopes(t *testing.T) {
	cli := &Config{
		Headers:     []core.KeyVal[string]{{Key: "X-CLI", Val: "1"}},
		QueryParams: []core.KeyVal[string]{{Key: "q", Val: "cli"}},
		CACerts:     []*x509.Certificate{{SerialNumber: big.NewInt(3)}},
	}
	host := &Config{
		Headers:     []core.KeyVal[string]{{Key: "X-Host", Val: "1"}},
		QueryParams: []core.KeyVal[string]{{Key: "q", Val: "host"}},
		CACerts:     []*x509.Certificate{{SerialNumber: big.NewInt(2)}},
	}
	global := &Config{
		Headers:     []core.KeyVal[string]{{Key: "X-Global", Val: "1"}},
		QueryParams: []core.KeyVal[string]{{Key: "q", Val: "global"}},
		CACerts:     []*x509.Certificate{{SerialNumber: big.NewInt(1)}},
	}

	cli.Merge(host)
	cli.Merge(global)
	if got := cli.Headers; !reflect.DeepEqual(got, []core.KeyVal[string]{
		{Key: "X-Global", Val: "1"}, {Key: "X-Host", Val: "1"}, {Key: "X-CLI", Val: "1"},
	}) {
		t.Fatalf("headers = %+v", got)
	}
	if got := cli.QueryParams; !reflect.DeepEqual(got, []core.KeyVal[string]{
		{Key: "q", Val: "global"}, {Key: "q", Val: "host"}, {Key: "q", Val: "cli"},
	}) {
		t.Fatalf("query params = %+v", got)
	}
	for i, cert := range cli.CACerts {
		if cert.SerialNumber.Int64() != int64(i+1) {
			t.Fatalf("CA certificate %d serial = %d", i, cert.SerialNumber.Int64())
		}
	}
}

func TestMergeReportsOnlyContributingOptions(t *testing.T) {
	cliTimeout := 3 * time.Second
	hostTimeout := 2 * time.Second
	globalTimeout := 1 * time.Second
	cli := &Config{
		Timeout: &cliTimeout,
		Headers: []core.KeyVal[string]{{Key: "X-CLI", Val: "1"}},
	}
	host := &Config{
		Timeout: &hostTimeout,
		Headers: []core.KeyVal[string]{{Key: "X-Host", Val: "1"}},
	}
	global := &Config{
		Timeout: &globalTimeout,
		Headers: []core.KeyVal[string]{{Key: "X-Global", Val: "1"}},
	}

	if got := cli.Merge(host); !reflect.DeepEqual(got, []string{"header"}) {
		t.Fatalf("host merge keys = %v, want [header]", got)
	}
	if got := cli.Merge(global); !reflect.DeepEqual(got, []string{"header"}) {
		t.Fatalf("global merge keys = %v, want [header]", got)
	}
	if *cli.Timeout != cliTimeout {
		t.Fatalf("timeout = %s, want CLI timeout %s", *cli.Timeout, cliTimeout)
	}
	if !reflect.DeepEqual(cli.Headers, []core.KeyVal[string]{
		{Key: "X-Global", Val: "1"},
		{Key: "X-Host", Val: "1"},
		{Key: "X-CLI", Val: "1"},
	}) {
		t.Fatalf("merged headers = %+v", cli.Headers)
	}
}

func TestFileHostConfig(t *testing.T) {
	exactCfg := &Config{isFile: true, Insecure: new(true)}
	wildcardCfg := &Config{isFile: true, Insecure: new(false)}
	specificWildcardCfg := &Config{isFile: true, NoPager: new(true)}

	f := &File{
		Global: &Config{isFile: true},
		Hosts: map[string]*Config{
			"api.example.com":   exactCfg,
			"*.example.com":     wildcardCfg,
			"*.api.example.com": specificWildcardCfg,
		},
	}

	tests := []struct {
		name     string
		hostname string
		expected *Config
	}{
		{
			name:     "exact match",
			hostname: "api.example.com",
			expected: exactCfg,
		},
		{
			name:     "case-insensitive exact match",
			hostname: "API.Example.com",
			expected: exactCfg,
		},
		{
			name:     "wildcard match",
			hostname: "www.example.com",
			expected: wildcardCfg,
		},
		{
			name:     "case-insensitive wildcard match",
			hostname: "WWW.Example.com",
			expected: wildcardCfg,
		},
		{
			name:     "wildcard does not match base domain",
			hostname: "example.com",
			expected: nil,
		},
		{
			name:     "deeply nested subdomain matches wildcard",
			hostname: "a.b.example.com",
			expected: wildcardCfg,
		},
		{
			name:     "most specific wildcard wins",
			hostname: "v1.api.example.com",
			expected: specificWildcardCfg,
		},
		{
			name:     "case-insensitive most specific wildcard wins",
			hostname: "V1.API.Example.com",
			expected: specificWildcardCfg,
		},
		{
			name:     "no match",
			hostname: "other.com",
			expected: nil,
		},
		{
			name:     "empty hostname",
			hostname: "",
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := f.HostConfig(test.hostname)
			if got != test.expected {
				t.Fatalf("HostConfig(%q) = %v, want %v", test.hostname, got, test.expected)
			}
		})
	}

	// Test with nil Hosts map.
	t.Run("nil hosts map", func(t *testing.T) {
		nilFile := &File{Global: &Config{isFile: true}}
		got := nilFile.HostConfig("example.com")
		if got != nil {
			t.Fatalf("HostConfig with nil Hosts = %v, want nil", got)
		}
	})
}
