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
