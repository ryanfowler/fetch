package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/cli"
	"github.com/ryanfowler/fetch/internal/config"
	"github.com/ryanfowler/fetch/internal/core"
)

func TestHelpVerboseRequested(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "ordinary help", args: []string{"--help"}},
		{name: "long flags", args: []string{"--verbose", "--help"}, want: true},
		{name: "short flags", args: []string{"-vh"}, want: true},
		{name: "clustered verbose flags", args: []string{"-vv", "-h"}, want: true},
		{name: "after positional", args: []string{"example.com", "--help", "-v"}, want: true},
		{name: "after separator", args: []string{"--", "--help", "-v"}},
	}
	app, err := cli.Parse(nil)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := helpVerboseRequested(test.args, app); got != test.want {
				t.Fatalf("helpVerboseRequested(%q) = %t, want %t", test.args, got, test.want)
			}
		})
	}

	t.Run("does not treat an option value as verbose", func(t *testing.T) {
		if helpVerboseRequested([]string{"--method", "-v", "--help"}, app) {
			t.Fatal("method value was treated as a verbosity flag")
		}
	})
}

func TestParseConfigFileMergesScopesAndRecordsProvenance(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config")
	configData := []byte("header = X-Global: global\nquery = scope=global\n\n[example.com]\nheader = X-Host: host\nquery = scope=host\n")
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		t.Fatalf("unable to write config: %v", err)
	}

	app, err := cli.Parse([]string{
		"--config", configPath,
		"--header", "X-CLI: cli",
		"--query", "scope=cli",
		"https://example.com",
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if _, err := parseConfigFile(app); err != nil {
		t.Fatalf("parseConfigFile() error = %v", err)
	}

	if got := app.Cfg.Headers; !slices.Equal(got, []core.KeyVal[string]{
		{Key: "X-Global", Val: "global"},
		{Key: "X-Host", Val: "host"},
		{Key: "X-CLI", Val: "cli"},
	}) {
		t.Fatalf("headers = %+v", got)
	}
	if got := app.Cfg.QueryParams; !slices.Equal(got, []core.KeyVal[string]{
		{Key: "scope", Val: "global"},
		{Key: "scope", Val: "host"},
		{Key: "scope", Val: "cli"},
	}) {
		t.Fatalf("query params = %+v", got)
	}
	for _, name := range []string{"header", "query"} {
		provenance := app.OptionProvenance(name)
		for _, source := range []cli.OptionSource{cli.SourceGlobalConfig, cli.SourceHostConfig, cli.SourceCLI} {
			if !provenance.Has(source) {
				t.Fatalf("%s provenance = %v, missing %v", name, provenance.Sources, source)
			}
		}
	}
}

func TestMetadataPresentationFlags(t *testing.T) {
	app, err := cli.Parse([]string{"--pager", "on", "-v", "--help"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if app.Cfg.Pager != core.PagerOn {
		t.Fatalf("pager mode = %v, want on", app.Cfg.Pager)
	}
	if getValue(app.Cfg.NoPager) {
		t.Fatal("--pager on unexpectedly enabled no-pager")
	}
}

func TestBuildInfoIncludesTargetSettingsAndOptionalDependencies(t *testing.T) {
	compact := string(core.GetBuildInfo())
	if !strings.Contains(compact, `"target_os"`) || !strings.Contains(compact, `"target_arch"`) {
		t.Fatalf("compact build info lacks target settings: %s", compact)
	}
	if strings.Contains(compact, `"deps"`) {
		t.Fatalf("compact build info unexpectedly includes dependencies: %s", compact)
	}
	verbose := string(core.GetBuildInfo(true))
	if !strings.Contains(verbose, `"deps"`) {
		t.Fatalf("verbose build info lacks dependencies: %s", verbose)
	}
}

func TestIgnoredInspectionFlags(t *testing.T) {
	app := inspectionFlagTestApp(t)

	common := []string{
		"--data/--json/--xml",
		"--form",
		"--multipart",
		"--grpc",
		"--grpc-describe",
		"--grpc-list",
		"--output",
		"--remote-name",
		"--remote-header-name",
		"--copy",
		"--method",
		"--header",
		"--query",
		"--edit",
		"--session",
		"--retry",
		"--range",
		"--timing",
		"--proxy",
		"--discard",
		"--unix",
	}

	if got := ignoredInspectionFlags(app, inspectionTLS); !slices.Equal(got, common) {
		t.Fatalf("ignoredInspectionFlags(inspectionTLS) = %v, want %v", got, common)
	}

	wantDNS := append(slices.Clone(common),
		"--inspect-tls",
		"--bearer",
		"--basic",
		"--digest",
		"--aws-sigv4",
		"--cert",
		"--key",
		"--format",
		"--dry-run",
	)
	if got := ignoredInspectionFlags(app, inspectionDNS); !slices.Equal(got, wantDNS) {
		t.Fatalf("ignoredInspectionFlags(inspectionDNS) = %v, want %v", got, wantDNS)
	}
}

func TestWarnIgnoredInspectionFlagsDoesNotAddBlankLine(t *testing.T) {
	p := core.TestPrinter(false)

	warnIgnoredInspectionFlags(p, inspectionDNS, []string{"--timing"})

	got := string(p.Bytes())
	want := "warning: --inspect-dns ignores: --timing\n"
	if got != want {
		t.Fatalf("warning output = %q, want %q", got, want)
	}
}

func TestIgnoredInspectionFlagsRequireExplicitProvenance(t *testing.T) {
	configOnly := &cli.App{Cfg: config.Config{
		Headers: []core.KeyVal[string]{{Key: "X-Config", Val: "yes"}},
	}}
	configOnly.RecordConfigSource(&configOnly.Cfg, cli.SourceGlobalConfig)
	if got := ignoredInspectionFlags(configOnly, inspectionDNS); len(got) != 0 {
		t.Fatalf("config-only inspection flags = %v, want none", got)
	}

	explicit, err := cli.Parse([]string{"--header", "X-CLI: yes", "https://example.com"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := ignoredInspectionFlags(explicit, inspectionDNS); !slices.Equal(got, []string{"--header"}) {
		t.Fatalf("explicit inspection flags = %v, want [--header]", got)
	}

	fromCurl, err := cli.Parse([]string{"--from-curl", "curl -H 'X-Curl: yes' https://example.com"})
	if err != nil {
		t.Fatalf("Parse(--from-curl) error = %v", err)
	}
	if got := ignoredInspectionFlags(fromCurl, inspectionDNS); !slices.Equal(got, []string{"--header"}) {
		t.Fatalf("curl inspection flags = %v, want [--header]", got)
	}

	fromCurlMultipart, err := cli.Parse([]string{"--from-curl", "curl -F field=value https://example.com"})
	if err != nil {
		t.Fatalf("Parse(--from-curl multipart) error = %v", err)
	}
	if got := ignoredInspectionFlags(fromCurlMultipart, inspectionDNS); !slices.Equal(got, []string{"--multipart", "--method"}) {
		t.Fatalf("curl multipart inspection flags = %v, want [--multipart --method]", got)
	}
}

func inspectionFlagTestApp(t *testing.T) *cli.App {
	t.Helper()

	copyOutput := true
	insecure := true
	retry := 1
	session := "session-name"
	timing := true
	tlsMax := uint16(tls.VersionTLS13)
	tlsMin := uint16(tls.VersionTLS12)
	proxyURL, err := url.Parse("http://proxy.test")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	return &cli.App{
		AWSSigv4:         &aws.Config{},
		Basic:            &core.KeyVal[string]{Key: "user", Val: "pass"},
		Bearer:           "token",
		Data:             strings.NewReader("body"),
		Digest:           &core.KeyVal[string]{Key: "user", Val: "pass"},
		Discard:          true,
		DryRun:           true,
		Edit:             true,
		Form:             []core.KeyVal[string]{{Key: "field", Val: "value"}},
		GRPC:             true,
		GRPCDescribe:     "service.Method",
		GRPCList:         true,
		InspectTLS:       true,
		Method:           "POST",
		Multipart:        []core.KeyVal[string]{{Key: "file", Val: "path"}},
		Output:           "out.txt",
		Range:            []string{"0-10"},
		RemoteHeaderName: true,
		RemoteName:       true,
		UnixSocket:       "/tmp/fetch.sock",
		Cfg: config.Config{
			CACerts:     []*x509.Certificate{{}},
			CertPath:    "client.pem",
			Copy:        &copyOutput,
			Format:      core.FormatOn,
			Headers:     []core.KeyVal[string]{{Key: "X-Test", Val: "1"}},
			Insecure:    &insecure,
			KeyPath:     "client-key.pem",
			Proxy:       proxyURL,
			QueryParams: []core.KeyVal[string]{{Key: "q", Val: "1"}},
			Retry:       &retry,
			Session:     &session,
			Timing:      &timing,
			TLSMax:      &tlsMax,
			TLSMin:      &tlsMin,
		},
	}
}
