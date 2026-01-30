package config

import (
	"crypto/tls"
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
			config: `[*.example.com]
				insecure = true`,
			expFile: &File{
				Global: &Config{isFile: true},
				Hosts: map[string]*Config{
					"*.example.com": {
						isFile:   true,
						Insecure: core.PointerTo(true),
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
				tls = 1.3`,
			expFile: &File{
				Global: &Config{
					isFile:  true,
					Timeout: core.PointerTo(10 * time.Second),
					TLS:     core.PointerTo(uint16(tls.VersionTLS13)),
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
				
				[example.com]
				insecure = true

				[anotherhost.com]
				ignore-status = true`,
			expFile: &File{
				Global: &Config{
					isFile:  true,
					Color:   core.ColorOff,
					NoPager: core.PointerTo(true),
				},
				Hosts: map[string]*Config{
					"example.com": {
						isFile:   true,
						Insecure: core.PointerTo(true),
					},
					"anotherhost.com": {
						isFile:       true,
						IgnoreStatus: core.PointerTo(true),
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

func TestFileHostConfig(t *testing.T) {
	exactCfg := &Config{isFile: true, Insecure: core.PointerTo(true)}
	wildcardCfg := &Config{isFile: true, Insecure: core.PointerTo(false)}
	specificWildcardCfg := &Config{isFile: true, NoPager: core.PointerTo(true)}

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
			name:     "wildcard match",
			hostname: "www.example.com",
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
