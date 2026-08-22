package cli

import (
	"crypto/tls"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestTLSFlags(t *testing.T) {
	t.Run("tls remains minimum version alias", func(t *testing.T) {
		app, err := Parse([]string{"--tls", "1.2", "https://example.com"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.Cfg.TLSMin == nil || *app.Cfg.TLSMin != tls.VersionTLS12 {
			t.Fatalf("TLSMin = %v, want TLS 1.2", app.Cfg.TLSMin)
		}
	})

	t.Run("min and max tls", func(t *testing.T) {
		app, err := Parse([]string{"--min-tls", "1.2", "--max-tls", "1.3", "https://example.com"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.Cfg.TLSMin == nil || *app.Cfg.TLSMin != tls.VersionTLS12 {
			t.Fatalf("TLSMin = %v, want TLS 1.2", app.Cfg.TLSMin)
		}
		if app.Cfg.TLSMax == nil || *app.Cfg.TLSMax != tls.VersionTLS13 {
			t.Fatalf("TLSMax = %v, want TLS 1.3", app.Cfg.TLSMax)
		}
	})

	t.Run("rejects invalid tls range", func(t *testing.T) {
		_, err := Parse([]string{"--min-tls", "1.3", "--max-tls", "1.2", "https://example.com"})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "max-tls") {
			t.Fatalf("error = %q, want max-tls", err.Error())
		}
	})

	for _, version := range []string{"1.0", "1.1"} {
		t.Run("rejects legacy TLS "+version, func(t *testing.T) {
			_, err := Parse([]string{"--min-tls", version, "https://example.com"})
			if err == nil {
				t.Fatal("expected legacy TLS version to be rejected")
			}
			if !strings.Contains(err.Error(), "1.2") || !strings.Contains(err.Error(), "1.3") {
				t.Fatalf("error = %q, want supported version list", err)
			}
		})
	}

	t.Run("rejects TLS 1.2 maximum for HTTP/3", func(t *testing.T) {
		app, err := Parse([]string{"--http3", "--max-tls", "1.2", "https://example.com"})
		if err == nil {
			err = app.Cfg.Validate()
		}
		if err == nil || !strings.Contains(err.Error(), "HTTP/3") {
			t.Fatalf("Parse() error = %v, want HTTP/3 TLS error", err)
		}
	})
}

func TestCLI002TargetFlags(t *testing.T) {
	t.Run("article", func(t *testing.T) {
		app, err := Parse([]string{"--article", "https://example.com"})
		if err != nil || !app.Article {
			t.Fatalf("Parse() = app=%+v, err=%v", app, err)
		}
	})

	for _, mode := range []struct {
		name string
		want core.CompressionMode
	}{
		{"auto", core.CompressionAuto}, {"br", core.CompressionBrotli},
		{"brotli", core.CompressionBrotli}, {"gzip", core.CompressionGzip},
		{"zstd", core.CompressionZstd}, {"off", core.CompressionOff},
	} {
		t.Run("compress/"+mode.name, func(t *testing.T) {
			app, err := Parse([]string{"--compress", mode.name, "https://example.com"})
			if err != nil || app.Cfg.Compress != mode.want {
				t.Fatalf("Parse() = compress=%v, err=%v; want %v", app.Cfg.Compress, err, mode.want)
			}
		})
	}

	for _, mode := range []string{"auto", "on", "off"} {
		t.Run("ech/"+mode, func(t *testing.T) {
			app, err := Parse([]string{"--ech", mode, "https://example.com"})
			if err != nil || app.Cfg.ECH == core.ECHUnknown {
				t.Fatalf("Parse() = ech=%v, err=%v", app.Cfg.ECH, err)
			}
		})
	}

	for _, version := range []struct {
		flag string
		want core.HTTPVersion
	}{
		{"--http1", core.HTTP1}, {"--http2", core.HTTP2}, {"--http3", core.HTTP3},
	} {
		t.Run(version.flag, func(t *testing.T) {
			app, err := Parse([]string{version.flag, "https://example.com"})
			if err != nil || app.Cfg.HTTP != version.want {
				t.Fatalf("Parse() = http=%v, err=%v; want %v", app.Cfg.HTTP, err, version.want)
			}
		})
	}

	app, err := Parse([]string{
		"--har", "capture.har", "--image", "external", "--pager", "on",
		"--sort-headers",
		"https://example.com",
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if app.HAR != "capture.har" || app.Cfg.Image != core.ImageExternal || app.Cfg.Pager != core.PagerOn ||
		app.Cfg.SortHeaders == nil || !*app.Cfg.SortHeaders {
		t.Fatalf("parsed target flags were not retained: %+v", app)
	}
	if app, err := Parse([]string{"--ws-message-mode", "binary", "ws://example.com"}); err != nil || app.WSMessageMode != core.WSMessageBinary {
		t.Fatalf("WebSocket message mode = %v, err %v", app.WSMessageMode, err)
	}
	if app, err := Parse([]string{"--install-skill", "--scope", "project", "--force"}); err != nil || app.InstallSkill != "auto" || app.Scope != "project" || !app.Force {
		t.Fatalf("skill options = %+v, err %v", app, err)
	}

	for _, args := range [][]string{
		{"--install-skill"},
		{"--install-skill", "codex"},
		{"--uninstall-skill=all"},
		{"--skill"},
	} {
		if _, err := Parse(args); err != nil {
			t.Errorf("Parse(%v) error = %v", args, err)
		}
	}

	if app, err := Parse([]string{"--no-encode", "https://example.com"}); err != nil || app.Cfg.Compress != core.CompressionOff {
		t.Fatalf("--no-encode = compress %v, err %v; want off", app.Cfg.Compress, err)
	}
	if app, err := Parse([]string{"--compress", "off", "--no-encode", "https://example.com"}); err != nil || app.Cfg.Compress != core.CompressionOff {
		t.Fatalf("equivalent compression aliases = compress %v, err %v; want off", app.Cfg.Compress, err)
	}
	if app, err := Parse([]string{"--pager", "off", "--no-pager", "https://example.com"}); err != nil || app.Cfg.Pager != core.PagerOff {
		t.Fatalf("equivalent pager aliases = pager %v, err %v; want off", app.Cfg.Pager, err)
	}
}

func TestCLI002Validation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"invalid compress", []string{"--compress", "deflate", "https://example.com"}, "compress"},
		{"invalid scope", []string{"--scope", "global"}, "scope"},
		{"scope requires operation", []string{"--scope", "project"}, "requires"},
		{"force requires operation", []string{"--force"}, "requires"},
		{"article discard", []string{"--article", "--discard", "https://example.com"}, "article"},
		{"article grpc", []string{"--article", "--grpc", "https://example.com"}, "article"},
		{"article dns inspection", []string{"--article", "--inspect-dns", "https://example.com"}, "article"},
		{"article tls inspection", []string{"--article", "--inspect-tls", "https://example.com"}, "article"},
		{"article websocket", []string{"--article", "ws://example.com"}, "article"},
		{"har stdout", []string{"--har", "-", "https://example.com"}, "har"},
		{"har empty", []string{"--har=", "https://example.com"}, "har"},
		{"compression conflict", []string{"--compress", "gzip", "--no-encode", "https://example.com"}, "compress"},
		{"pager conflict", []string{"--pager", "on", "--no-pager", "https://example.com"}, "pager"},
		{"repeated compression conflict", []string{"--compress", "gzip", "--compress", "zstd", "https://example.com"}, "compress"},
		{"invalid skill agent", []string{"--install-skill", "bogus"}, "install-skill"},
		{"skill URL", []string{"--skill", "https://example.com"}, "skill"},
		{"message mode URL", []string{"--ws-message-mode", "auto", "https://example.com"}, "ws://"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse(%v) error = %v, want text containing %q", test.args, err, test.want)
			}
		})
	}
}

func TestFlagsAlphabeticalOrder(t *testing.T) {
	app, err := Parse(nil)
	if err != nil {
		t.Fatalf("unable to parse cli: %s", err.Error())
	}
	cli := app.CLI()
	for i := 1; i < len(cli.Flags); i++ {
		prev := cli.Flags[i-1].Long
		curr := cli.Flags[i].Long
		if curr < prev {
			t.Errorf("flags out of alphabetical order: %q should come before %q", curr, prev)
		}
	}
}

func TestOptionRegistryMetadataAndAliases(t *testing.T) {
	var app App
	registry := app.CLI().Options()
	flags := registry.Flags()
	if len(flags) == 0 {
		t.Fatal("option registry is empty")
	}

	for _, flag := range flags {
		if flag.Long == "" {
			t.Fatal("registry contains an option without a canonical name")
		}
		if flag.ConfigKey == "" {
			t.Fatalf("--%s has no config key metadata", flag.Long)
		}
		if len(flag.Modes) == 0 {
			t.Fatalf("--%s has no mode metadata", flag.Long)
		}
		got, ok := registry.Lookup(flag.Long)
		if !ok || got.Long != flag.Long {
			t.Fatalf("registry lookup for --%s = %+v, %v", flag.Long, got, ok)
		}
		for _, alias := range flag.Aliases {
			got, ok := registry.Lookup(alias)
			if !ok || got.Long != flag.Long {
				t.Fatalf("alias %q resolved to %+v, %v; want --%s", alias, got, ok, flag.Long)
			}
		}
	}

	if !registry.byName["header"].Repeatable || !registry.byName["query"].Repeatable {
		t.Fatal("repeatable options are not represented in the registry")
	}
}

func TestCLI003URLNormalizationAndMethodInference(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		scheme string
		host   string
	}{
		{name: "hostname defaults to https", rawURL: "example.com/path", scheme: "https", host: "example.com"},
		{name: "ipv4 defaults to http", rawURL: "192.0.2.1/path", scheme: "http", host: "192.0.2.1"},
		{name: "ipv6 defaults to http", rawURL: "[2001:db8::1]/path", scheme: "http", host: "[2001:db8::1]"},
		{name: "scoped ipv6 defaults to http", rawURL: "[fe80::1%25lo]/path", scheme: "http", host: "[fe80::1%lo]"},
		{name: "localhost remains http", rawURL: "localhost/path", scheme: "http", host: "localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, err := Parse([]string{tt.rawURL})
			if err != nil {
				t.Fatal(err)
			}
			if app.URL.Scheme != tt.scheme || app.URL.Host != tt.host {
				t.Fatalf("URL = %s, want %s://%s", app.URL, tt.scheme, tt.host)
			}
			if !app.SchemelessURL {
				t.Fatal("schemeless URL was not recorded")
			}
		})
	}

	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{name: "data", args: []string{"--data", "body", "example.com"}, want: "POST"},
		{name: "json", args: []string{"--json", "{}", "example.com"}, want: "POST"},
		{name: "xml", args: []string{"--xml", "<x/>", "example.com"}, want: "POST"},
		{name: "form", args: []string{"--form", "key=value", "example.com"}, want: "POST"},
		{name: "multipart", args: []string{"--multipart", "key=value", "example.com"}, want: "POST"},
		{name: "edit", args: []string{"--edit", "example.com"}, want: "POST"},
		{name: "explicit method wins", args: []string{"--method", "GET", "--json", "{}", "example.com"}, want: "GET"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			app, err := Parse(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			if app.Method != tt.want {
				t.Fatalf("method = %q, want %q", app.Method, tt.want)
			}
		})
	}
}

func TestOptionProvenance(t *testing.T) {
	app, err := Parse([]string{"-X", "POST", "https://example.com"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !app.OptionProvenance("method").Has(SourceCLI) {
		t.Fatal("method alias did not record explicit CLI provenance")
	}
	if app.OptionProvenance("method").Has(SourceGlobalConfig) {
		t.Fatal("method unexpectedly recorded config provenance")
	}

	tlsApp, err := Parse([]string{"--tls", "1.2", "https://example.com"})
	if err != nil {
		t.Fatalf("Parse(--tls) error = %v", err)
	}
	if !tlsApp.OptionProvenance("tls").Has(SourceCLI) || !tlsApp.OptionProvenance("min-tls").Has(SourceCLI) {
		t.Fatal("TLS alias provenance was not canonicalized")
	}
}

func TestRegistryConflictsUseCanonicalNames(t *testing.T) {
	_, err := Parse([]string{"--basic", "user:pass", "--bearer", "token", "https://example.com"})
	if err == nil {
		t.Fatal("expected auth conflict")
	}
	if got := err.Error(); got != "flags '--basic' and '--bearer' cannot be used together" {
		t.Fatalf("error = %q, want canonical conflict names", got)
	}
}

func TestEndOfOptions(t *testing.T) {
	t.Run("normal parse treats remaining args as positional", func(t *testing.T) {
		app, err := Parse([]string{"--", "https://example.com"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.URL == nil || app.URL.String() != "https://example.com" {
			t.Fatalf("URL = %v, want https://example.com", app.URL)
		}
		if len(app.ExtraArgs) != 0 {
			t.Fatalf("ExtraArgs = %v, want none", app.ExtraArgs)
		}
	})

	t.Run("completion parse keeps remaining args as extra args", func(t *testing.T) {
		app, err := Parse([]string{"--complete=bash", "--", "fetch", "--"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.Complete != "bash" {
			t.Fatalf("Complete = %q, want bash", app.Complete)
		}
		want := []string{"fetch", "--"}
		if !slices.Equal(app.ExtraArgs, want) {
			t.Fatalf("ExtraArgs = %v, want %v", app.ExtraArgs, want)
		}
		if app.URL != nil {
			t.Fatalf("URL = %v, want nil", app.URL)
		}
	})
}

func TestHeaderFlag(t *testing.T) {
	t.Run("allows empty value", func(t *testing.T) {
		app, err := Parse([]string{"-H", "X-Test:", "https://example.com"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if len(app.Cfg.Headers) != 1 || app.Cfg.Headers[0].Key != "X-Test" || app.Cfg.Headers[0].Val != "" {
			t.Fatalf("Headers = %+v, want X-Test with empty value", app.Cfg.Headers)
		}
	})

	t.Run("rejects empty name", func(t *testing.T) {
		_, err := Parse([]string{"-H", ": value", "https://example.com"})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "--header") {
			t.Fatalf("error = %q, want --header", err.Error())
		}
	})
}

func TestWebSocketSchemeExclusives(t *testing.T) {
	tests := []struct {
		name string
		args []string
		flag string
	}{
		{name: "copy", args: []string{"ws://example.com", "--copy"}, flag: "copy"},
		{name: "output", args: []string{"ws://example.com", "--output", "out.txt"}, flag: "output"},
		{name: "remote name", args: []string{"ws://example.com", "--remote-name"}, flag: "remote-name"},
		{name: "retry", args: []string{"ws://example.com", "--retry", "1"}, flag: "retry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.args)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "--"+tt.flag) {
				t.Fatalf("error = %q, want --%s", err.Error(), tt.flag)
			}
		})
	}
}

func TestWebSocketInteractiveFlag(t *testing.T) {
	t.Run("parses off", func(t *testing.T) {
		app, err := Parse([]string{"ws://example.com", "--ws-interactive", "off"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.WSInteractive != core.WSInteractiveOff {
			t.Fatalf("WSInteractive = %v, want off", app.WSInteractive)
		}
	})

	t.Run("rejects invalid value", func(t *testing.T) {
		_, err := Parse([]string{"ws://example.com", "--ws-interactive", "maybe"})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "ws-interactive") {
			t.Fatalf("error = %q, want ws-interactive", err.Error())
		}
	})

	t.Run("requires websocket url", func(t *testing.T) {
		_, err := Parse([]string{"https://example.com", "--ws-interactive", "off"})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "ws://") {
			t.Fatalf("error = %q, want ws://", err.Error())
		}
	})
}

func TestFromCurlDataUrlencode(t *testing.T) {
	t.Run("@file reads and encodes contents", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "payload.txt")
		os.WriteFile(path, []byte("hello world&foo=bar"), 0o644)

		app, err := Parse([]string{
			"--from-curl",
			`curl --data-urlencode '@` + path + `' https://example.com`,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		body, _ := io.ReadAll(app.Data)
		got := string(body)
		want := "hello+world%26foo%3Dbar"
		if got != want {
			t.Fatalf("body = %q, want %q", got, want)
		}
	})

	t.Run("name@file reads and encodes contents with name prefix", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "data.txt")
		os.WriteFile(path, []byte("value with spaces"), 0o644)

		app, err := Parse([]string{
			"--from-curl",
			`curl --data-urlencode 'field@` + path + `' https://example.com`,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		body, _ := io.ReadAll(app.Data)
		got := string(body)
		want := "field=value+with+spaces"
		if got != want {
			t.Fatalf("body = %q, want %q", got, want)
		}
	})

	t.Run("inline name=content still works", func(t *testing.T) {
		app, err := Parse([]string{
			"--from-curl",
			`curl --data-urlencode "key=hello world" https://example.com`,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		body, _ := io.ReadAll(app.Data)
		got := string(body)
		want := "key=hello+world"
		if got != want {
			t.Fatalf("body = %q, want %q", got, want)
		}
	})
}

func TestFromCurlGetData(t *testing.T) {
	t.Run("-d @file expands contents into query", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "payload.txt")
		os.WriteFile(path, []byte("q=search&limit=10"), 0o644)

		app, err := Parse([]string{
			"--from-curl",
			`curl -G -d '@` + path + `' https://example.com`,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.Data != nil {
			t.Fatal("expected no request body for curl -G")
		}
		if app.URL.RawQuery != "q=search&limit=10" {
			t.Fatalf("RawQuery = %q, want %q", app.URL.RawQuery, "q=search&limit=10")
		}
	})

	t.Run("--data-urlencode name@file expands and encodes contents into query", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "data.txt")
		os.WriteFile(path, []byte("value with spaces&x=1"), 0o644)

		app, err := Parse([]string{
			"--from-curl",
			`curl -G --data-urlencode 'field@` + path + `' https://example.com?existing=1`,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.Data != nil {
			t.Fatal("expected no request body for curl -G")
		}
		want := "existing=1&field=value+with+spaces%26x%3D1"
		if app.URL.RawQuery != want {
			t.Fatalf("RawQuery = %q, want %q", app.URL.RawQuery, want)
		}
	})
}

func TestFromCurlRedirects(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want int
	}{
		{
			name: "disabled by default",
			cmd:  "curl https://example.com",
			want: 0,
		},
		{
			name: "max redirs alone does not follow",
			cmd:  "curl --max-redirs 5 https://example.com",
			want: 0,
		},
		{
			name: "location uses curl default limit",
			cmd:  "curl -L https://example.com",
			want: curlDefaultMaxRedirects,
		},
		{
			name: "location with max redirs",
			cmd:  "curl -L --max-redirs 5 https://example.com",
			want: 5,
		},
		{
			name: "location with explicit zero max redirs",
			cmd:  "curl -L --max-redirs 0 https://example.com",
			want: 0,
		},
		{
			name: "location with unlimited max redirs",
			cmd:  "curl -L --max-redirs -1 https://example.com",
			want: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, err := Parse([]string{"--from-curl", tt.cmd})
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if app.Cfg.Redirects == nil {
				t.Fatal("Redirects = nil, want explicit from-curl redirect setting")
			}
			if *app.Cfg.Redirects != tt.want {
				t.Fatalf("Redirects = %d, want %d", *app.Cfg.Redirects, tt.want)
			}
		})
	}
}

func TestFromCurlDataFileClose(t *testing.T) {
	// Verify that file descriptors are properly closed after reading.
	dir := t.TempDir()
	path := filepath.Join(dir, "body.txt")
	os.WriteFile(path, []byte("file content"), 0o644)

	app, err := Parse([]string{
		"--from-curl",
		`curl -d '@` + path + `' https://example.com`,
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	body, _ := io.ReadAll(app.Data)
	got := string(body)
	if got != "file content" {
		t.Fatalf("body = %q, want %q", got, "file content")
	}
}

func TestFromCurlCookieFileRejected(t *testing.T) {
	_, err := Parse([]string{
		"--from-curl",
		`curl -b cookies.txt https://example.com`,
	})
	if err == nil {
		t.Fatal("expected error for cookie file path, got nil")
	}
	if !strings.Contains(err.Error(), "cookie jar files are not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFromCurlMultipartFileValidation(t *testing.T) {
	t.Run("accepts existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "payload.txt")
		if err := os.WriteFile(path, []byte("file content"), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		app, err := Parse([]string{
			"--from-curl",
			`curl -F 'file=@` + path + `' https://example.com`,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if len(app.Multipart) != 1 {
			t.Fatalf("len(Multipart) = %d, want 1", len(app.Multipart))
		}
		if app.Multipart[0].Key != "file" || app.Multipart[0].Val != "@"+path {
			t.Fatalf("Multipart[0] = %#v, want file=@%s", app.Multipart[0], path)
		}
	})

	t.Run("rejects missing file during parse", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.txt")
		_, err := Parse([]string{
			"--from-curl",
			`curl -F 'file=@` + path + `' https://example.com`,
		})
		if err == nil {
			t.Fatal("expected missing file error, got nil")
		}
		if !strings.Contains(err.Error(), "file does not exist: '"+path+"'") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejects directory during parse", func(t *testing.T) {
		path := t.TempDir()
		_, err := Parse([]string{
			"--from-curl",
			`curl -F 'file=@` + path + `' https://example.com`,
		})
		if err == nil {
			t.Fatal("expected directory error, got nil")
		}
		if !strings.Contains(err.Error(), "file is a directory: '"+path+"'") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestCLI(t *testing.T) {
	app, err := Parse(nil)
	if err != nil {
		t.Fatalf("unable to parse cli: %s", err.Error())
	}
	p := core.NewHandle(core.ColorOff).Stdout()

	// Verify that no line of the help command is over 80 characters.
	app.PrintHelp(p)
	for line := range strings.Lines(string(p.Bytes())) {
		line = strings.TrimSuffix(line, "\n")
		if utf8.RuneCountInString(line) > 80 {
			t.Fatalf("line too long: %q", line)
		}
	}
}

func TestLongFlagExplicitEmptyValue(t *testing.T) {
	t.Run("does not consume following URL", func(t *testing.T) {
		app, err := Parse([]string{"--output=", "example.com"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.Output != "" {
			t.Fatalf("Output = %q, want empty string", app.Output)
		}
		if app.URL == nil {
			t.Fatal("expected URL to be parsed")
		}
		if app.URL.Host != "example.com" {
			t.Fatalf("URL host = %q, want %q", app.URL.Host, "example.com")
		}
	})

	t.Run("passes empty value to flag", func(t *testing.T) {
		app, err := Parse([]string{"--form=", "example.com"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if len(app.Form) != 1 {
			t.Fatalf("len(Form) = %d, want 1", len(app.Form))
		}
		if app.Form[0].Key != "" || app.Form[0].Val != "" {
			t.Fatalf("Form[0] = %#v, want empty key/value", app.Form[0])
		}
		if app.URL == nil {
			t.Fatal("expected URL to be parsed")
		}
		if app.URL.Host != "example.com" {
			t.Fatalf("URL host = %q, want %q", app.URL.Host, "example.com")
		}
	})
}

func TestRangeFlag(t *testing.T) {
	t.Run("accepts unsigned byte ranges", func(t *testing.T) {
		tests := []struct {
			name string
			arg  string
			want []string
		}{
			{name: "suffix", arg: "-1023", want: []string{"-1023"}},
			{name: "open ended", arg: "1023-", want: []string{"1023-"}},
			{name: "bounded", arg: "0-1023", want: []string{"0-1023"}},
			{name: "trimmed", arg: " 5 - 10 ", want: []string{"5-10"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				app, err := Parse([]string{"--range", tt.arg})
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
				}
				if len(app.Range) != len(tt.want) {
					t.Fatalf("Range = %v, want %v", app.Range, tt.want)
				}
				for i := range tt.want {
					if app.Range[i] != tt.want[i] {
						t.Fatalf("Range = %v, want %v", app.Range, tt.want)
					}
				}
			})
		}
	})

	t.Run("rejects signed or malformed byte ranges", func(t *testing.T) {
		tests := []string{
			"bad",
			"-",
			"5--1",
			"+5-10",
			"5-+10",
			"--1",
			"-+1",
		}

		for _, arg := range tests {
			t.Run(arg, func(t *testing.T) {
				_, err := Parse([]string{"--range", arg})
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), "invalid") {
					t.Fatalf("unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("validates ranges from curl commands", func(t *testing.T) {
		app, err := Parse([]string{"--from-curl", "curl -r 0-1023 https://example.com/file"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if len(app.Range) != 1 || app.Range[0] != "0-1023" {
			t.Fatalf("Range = %v, want [0-1023]", app.Range)
		}

		_, err = Parse([]string{"--from-curl", "curl -r 5--1 https://example.com/file"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid range end") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestGRPCDiscoveryFlags(t *testing.T) {
	t.Run("grpc list parses", func(t *testing.T) {
		app, err := Parse([]string{"--grpc-list", "localhost:50051"})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if !app.GRPCList {
			t.Fatal("expected GRPCList to be set")
		}
		if app.URL == nil {
			t.Fatal("expected URL to be parsed")
		}
	})

	t.Run("proto desc accepts grpc describe without url", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "service.pb")
		os.WriteFile(path, []byte("placeholder"), 0o644)

		app, err := Parse([]string{"--grpc-describe", "pkg.Service", "--proto-desc", path})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if app.GRPCDescribe != "pkg.Service" {
			t.Fatalf("GRPCDescribe = %q, want %q", app.GRPCDescribe, "pkg.Service")
		}
		if app.URL != nil {
			t.Fatal("expected URL to be optional for offline discovery")
		}
	})

	t.Run("proto desc requires grpc mode", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "service.pb")
		os.WriteFile(path, []byte("placeholder"), 0o644)

		_, err := Parse([]string{"--proto-desc", path})
		if err == nil {
			t.Fatal("expected error for proto-desc without grpc mode")
		}
		if !strings.Contains(err.Error(), "requires one of '--grpc', '--grpc-list', '--grpc-describe'") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("grpc discovery rejects request body flags", func(t *testing.T) {
		_, err := Parse([]string{"--grpc-list", "--data", "hello", "localhost:50051"})
		if err == nil {
			t.Fatal("expected error for grpc-list with data")
		}
		if !strings.Contains(err.Error(), "cannot be used together") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestDigestFlag(t *testing.T) {
	t.Run("digest auth parsing", func(t *testing.T) {
		app, err := Parse([]string{"--digest", "user:pass", "http://example.com"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if app.Digest == nil {
			t.Fatal("expected Digest to be set")
		}
		if app.Digest.Key != "user" || app.Digest.Val != "pass" {
			t.Fatalf("unexpected digest credentials: %q:%q", app.Digest.Key, app.Digest.Val)
		}
	})

	t.Run("digest auth preserves credential whitespace", func(t *testing.T) {
		app, err := Parse([]string{"--digest", " user : pass ", "http://example.com"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if app.Digest.Key != " user " || app.Digest.Val != " pass " {
			t.Fatalf("credentials = %q:%q, want whitespace preserved", app.Digest.Key, app.Digest.Val)
		}
	})

	t.Run("digest auth invalid format", func(t *testing.T) {
		_, err := Parse([]string{"--digest", "nocolon", "http://example.com"})
		if err == nil {
			t.Fatal("expected error for invalid digest format")
		}
		if !strings.Contains(err.Error(), "format must be") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("digest conflicts with basic", func(t *testing.T) {
		_, err := Parse([]string{"--digest", "user:pass", "--basic", "user:pass", "http://example.com"})
		if err == nil {
			t.Fatal("expected error for conflicting auth flags")
		}
		if !strings.Contains(err.Error(), "cannot be used together") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestAWSSigv4CredentialsAreNotLoadedDuringParse(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	app, err := Parse([]string{"--aws-sigv4", "us-east-1/s3", "https://example.com"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if app.AWSSigv4 == nil {
		t.Fatal("AWSSigv4 = nil, want config")
	}
	if app.AWSSigv4.Region != "us-east-1" || app.AWSSigv4.Service != "s3" {
		t.Fatalf("AWSSigv4 = %#v, want region us-east-1 and service s3", app.AWSSigv4)
	}
	if app.AWSSigv4.AccessKey != "" || app.AWSSigv4.SecretKey != "" {
		t.Fatalf("AWSSigv4 credentials = %q/%q, want empty", app.AWSSigv4.AccessKey, app.AWSSigv4.SecretKey)
	}
}

func TestFromCurlAWSSigv4CredentialsAreNotLoadedDuringParse(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	app, err := Parse([]string{"--from-curl", `curl --aws-sigv4 "aws:amz:us-east-1:s3" https://example.com`})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if app.AWSSigv4 == nil {
		t.Fatal("AWSSigv4 = nil, want config")
	}
	if app.AWSSigv4.Region != "us-east-1" || app.AWSSigv4.Service != "s3" {
		t.Fatalf("AWSSigv4 = %#v, want region us-east-1 and service s3", app.AWSSigv4)
	}
	if app.AWSSigv4.AccessKey != "" || app.AWSSigv4.SecretKey != "" {
		t.Fatalf("AWSSigv4 credentials = %q/%q, want empty", app.AWSSigv4.AccessKey, app.AWSSigv4.SecretKey)
	}
}
