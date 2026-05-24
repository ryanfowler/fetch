package integration_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/protobuf/encoding/protowire"
	protoMarshal "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

const fastRetryDelay = "0.000001"

func init() {
	if os.Getenv("FETCH_INTEGRATION_FAKE_EDITOR") != "1" {
		return
	}

	code := 0
	if raw := os.Getenv("FETCH_INTEGRATION_FAKE_EDITOR_EXIT"); raw != "" {
		var err error
		code, err = strconv.Atoi(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid FETCH_INTEGRATION_FAKE_EDITOR_EXIT: %v\n", err)
			os.Exit(2)
		}
	}
	if code == 0 {
		if len(os.Args) < 2 {
			fmt.Fprintln(os.Stderr, "missing editor target path")
			os.Exit(2)
		}
		path := os.Args[len(os.Args)-1]
		if err := os.WriteFile(path, []byte(os.Getenv("FETCH_INTEGRATION_FAKE_EDITOR_BODY")), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "writing fake editor body: %v\n", err)
			os.Exit(2)
		}
	}
	os.Exit(code)
}

func TestMain(t *testing.T) {
	fetchPath := testFetchBinary(t)
	version := getFetchVersion(t, fetchPath)

	t.Run("help", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--help")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufNotEmpty(t, res.stdout)
		assertBufContains(t, res.stdout, "[URL]  The URL to make a request to")
		assertBufContains(t, res.stdout, "--aws-sigv4 <REGION/SERVICE>  Sign the request using AWS signature V4")
		assertBufContains(t, res.stdout, "--format <OPTION>             Enable/disable formatting [auto, off, on]")
		for line := range strings.Lines(res.stdout.String()) {
			line = strings.TrimSuffix(line, "\n")
			if utf8.RuneCountInString(line) > 80 {
				t.Fatalf("help line too long: %q", line)
			}
		}
	})

	t.Run("no url", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath)
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "<URL> must be provided")

		res = runFetch(t, fetchPath, "--color", "on")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "\x1b[31m\x1b[1merror\x1b[0m: <URL> must be provided")
		assertBufContains(t, res.stderr, "\x1b[1m--help\x1b[0m")
	})

	t.Run("too many args", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "url1", "url2")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "unexpected argument")
	})

	t.Run("invalid flag", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--invalid")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "error: unknown flag '--invalid'")
		assertBufNotContains(t, res.stderr, "Usage:")

		res = runFetch(t, fetchPath, "--color", "on", "--invalid")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "\x1b[31m\x1b[1merror\x1b[0m: unknown flag '--invalid'")
		assertBufContains(t, res.stderr, "\x1b[1m--help\x1b[0m")
	})

	t.Run("conflicting flags", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--basic", "user:pass", "--bearer", "token")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "error: flags '--basic' and '--bearer' cannot be used together")
		assertBufNotContains(t, res.stderr, "Usage:")
	})

	t.Run("missing flag argument", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--output")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "error: argument required for flag '--output'")
		assertBufNotContains(t, res.stderr, "Usage:")
	})

	t.Run("flag with disallowed value", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--help=1")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "error: flag '--help' does not take any arguments")
		assertBufNotContains(t, res.stderr, "Usage:")
	})

	t.Run("invalid proxy flag", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--proxy", ":bad", "http://example.com")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "invalid value ':bad' for option '--proxy'")
		assertBufContains(t, res.stderr, "missing protocol scheme")
	})

	t.Run("shell completion", func(t *testing.T) {
		t.Parallel()

		res := runFetch(t, fetchPath, "--complete", "bash")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufContains(t, res.stdout, "_fetch_complete()")
		assertBufContains(t, res.stdout, "complete -o nosort -o nospace")

		res = runFetch(t, fetchPath, "--complete", "fish", "--", "fetch", "--col")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufEquals(t, res.stdout, "--color\tEnable/disable color\n")

		res = runFetch(t, fetchPath, "--complete", "bash", "--", "fetch", "--color", "o")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufEquals(t, res.stdout, "off \non \n")

		res = runFetch(t, fetchPath, "--complete", "powershell")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "completions not supported for shell 'powershell'")
	})

	t.Run("verbosity", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Custom-Header", "value")
			w.WriteHeader(200)
			io.WriteString(w, "hello")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "HTTP/1.1 200 OK")
		assertBufContains(t, res.stderr, "HTTP/1.1 200 OK\n\n")
		assertBufNotContains(t, res.stderr, "user-agent")
		assertBufNotContains(t, res.stderr, "x-custom-header")
		assertBufEquals(t, res.stdout, "hello")

		res = runFetch(t, fetchPath, server.URL, "-s")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufEquals(t, res.stdout, "hello")

		res = runFetch(t, fetchPath, server.URL, "-v")
		assertExitCode(t, 0, res)
		assertBufNotContains(t, res.stderr, "user-agent")
		assertBufContains(t, res.stderr, "x-custom-header")
		assertBufEquals(t, res.stdout, "hello")

		res = runFetch(t, fetchPath, server.URL, "-vv")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "> GET / HTTP/1.1")
		assertBufContains(t, res.stderr, "> user-agent")
		assertBufContains(t, res.stderr, "< x-custom-header")
		assertBufContains(t, res.stderr, "< HTTP/1.1 200 OK")
		assertBufNotContains(t, res.stderr, "* ")
		assertBufEquals(t, res.stdout, "hello")

		res = runFetch(t, fetchPath, server.URL, "-vv", "--color", "on")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "\x1b[1m\x1b[33mGET\x1b[0m")
		assertBufContains(t, res.stderr, "\x1b[1m\x1b[34muser-agent\x1b[0m")
		assertBufContains(t, res.stderr, "\x1b[32m\x1b[1m200\x1b[0m")
		assertBufContains(t, res.stderr, "\x1b[1m\x1b[36mx-custom-header\x1b[0m")
		assertBufEquals(t, res.stdout, "hello")

		res = runFetch(t, fetchPath, server.URL, "-vvv")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "> GET / HTTP/1.1")
		assertBufContains(t, res.stderr, "< HTTP/1.1 200 OK")
		assertBufContains(t, res.stderr, "* TCP:")
		assertBufContains(t, res.stderr, "* TTFB:")

		configPath := filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(configPath, []byte("format = off\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		res = runFetch(t, fetchPath, "--config", configPath, server.URL, "-vvv", "--color", "on")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "\x1b[1m\x1b[33mConfig\x1b[0m")
		assertBufContains(t, res.stderr, configPath)
		assertBufContains(t, res.stderr, "\x1b[1m\x1b[33mTCP\x1b[0m")
		assertBufContains(t, res.stderr, "\x1b[1m\x1b[33mTTFB\x1b[0m")
		assertBufContains(t, res.stderr, "\x1b[2m< \x1b[0m\n")

		localhostURL := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
		if localhostURL != server.URL {
			res = runFetch(t, fetchPath, localhostURL, "-vvv", "--color", "on")
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "\x1b[1m\x1b[33mDNS\x1b[0m: localhost")
			assertBufContains(t, res.stderr, "\x1b[3m127.0.0.1\x1b[0m")
		}
	})

	t.Run("default scheme loopback", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil {
				http.Error(w, "expected plaintext loopback request", http.StatusBadRequest)
				return
			}
			if r.URL.Query().Get("probe") != "1" {
				http.Error(w, "missing query", http.StatusBadRequest)
				return
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		target := strings.TrimPrefix(server.URL, "http://") + "?probe=1"
		res := runFetch(t, fetchPath, target)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("dry-run prints request headers and body", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "-j", `{"key":"val1"}`, "localhost:3000", "--dry-run")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "GET / HTTP/1.1\n")
		assertBufContains(t, res.stderr, "accept: application/json,application/vnd.msgpack,application/xml,image/webp,*/*\n")
		assertBufContains(t, res.stderr, "accept-encoding: gzip, zstd\n")
		assertBufContains(t, res.stderr, "content-length: 14\n")
		assertBufContains(t, res.stderr, "content-type: application/json\n")
		assertBufContains(t, res.stderr, "host: localhost:3000\n")
		assertBufContains(t, res.stderr, "user-agent: fetch/"+version)
		assertBufContains(t, res.stderr, "\n\n{\"key\":\"val1\"}")
		assertBufNotContains(t, res.stderr, "> GET")

		res = runFetch(t, fetchPath, "-j", `{"key":"val1"}`, "localhost:3000", "--dry-run", "--color", "on")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "\x1b[1m\x1b[33mGET\x1b[0m")
		assertBufContains(t, res.stderr, "\x1b[1m\x1b[36m/\x1b[0m")
		assertBufContains(t, res.stderr, "\x1b[2mHTTP/1.1\x1b[0m")
		assertBufContains(t, res.stderr, "\x1b[1m\x1b[34mhost\x1b[0m: localhost:3000")
		assertBufContains(t, res.stderr, "\n\n{\"key\":\"val1\"}")
	})

	t.Run("config color", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"ok":"yes"}`)
		})
		defer server.Close()

		path := filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(path, []byte("color = on\nformat = on\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runFetch(t, fetchPath, "--config", path, server.URL)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "\x1b[")
	})

	t.Run("cli color and format flags", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"ok":"yes"}`)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on", "--color", "on")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "\x1b[")
		assertBufContains(t, res.stdout, "yes")

		res = runFetch(t, fetchPath, server.URL, "--format", "on", "--color", "off")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "{\n  \"ok\": \"yes\"\n}\n")

		res = runFetch(t, fetchPath, server.URL, "--format", "off", "--color", "on")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, `{"ok":"yes"}`)
	})

	t.Run("config request options", func(t *testing.T) {
		t.Parallel()
		var attempts atomic.Int32
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			if query.Get("global") != "1" || query.Get("host") != "1" || query.Get("cli") != "1" {
				http.Error(w, "missing query", http.StatusBadRequest)
				return
			}
			if r.Header.Get("X-Global") != "yes" || r.Header.Get("X-Host") != "yes" || r.Header.Get("X-Cli") != "yes" {
				http.Error(w, "missing header", http.StatusBadRequest)
				return
			}
			if attempts.Add(1) == 1 {
				http.Error(w, "retry me", http.StatusServiceUnavailable)
				return
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		serverURL, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "config")
		config := fmt.Sprintf(`
format = off
retry = 1
retry-delay = %s
header = X-Global: yes
query = global=1

[%s]
header = X-Host: yes
query = host=1
`, fastRetryDelay, serverURL.Hostname())
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runFetch(t, fetchPath, "--config", path, "-H", "X-Cli: yes", "-q", "cli=1", server.URL)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "ok")
		if got := attempts.Load(); got != 2 {
			t.Fatalf("attempts = %d, want 2", got)
		}
	})

	t.Run("config duplicate host section replaces previous section", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			if query.Get("old") != "" || r.Header.Get("X-Old") != "" {
				http.Error(w, "old duplicate host section values leaked", http.StatusBadRequest)
				return
			}
			if query.Get("new") != "1" || r.Header.Get("X-New") != "yes" {
				http.Error(w, "new duplicate host section values missing", http.StatusBadRequest)
				return
			}
			io.WriteString(w, "duplicate")
		})
		defer server.Close()

		serverURL, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "config")
		config := fmt.Sprintf(`
format = off

[%s]
header = X-Old: yes
query = old=1

[%s]
header = X-New: yes
query = new=1
`, serverURL.Hostname(), serverURL.Hostname())
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runFetch(t, fetchPath, "--config", path, server.URL)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "duplicate")
	})

	t.Run("config TLS PEM validation", func(t *testing.T) {
		t.Parallel()
		var requests atomic.Int32
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			io.WriteString(w, "unexpected")
		})
		defer server.Close()

		dir := t.TempDir()
		notCertPath := writeTempPEM(t, dir, "not-client-cert.pem", "RSA PRIVATE KEY", []byte("fake"))
		configPath := filepath.Join(dir, "config")
		if err := os.WriteFile(configPath, []byte("cert = "+notCertPath+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runFetch(t, fetchPath, "--config", configPath, server.URL)
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "config file")
		assertBufContains(t, res.stderr, "line 1")
		assertBufContains(t, res.stderr, "invalid client certificate")
		assertBufContains(t, res.stderr, "expected CERTIFICATE, got RSA PRIVATE KEY")
		if got := requests.Load(); got != 0 {
			t.Fatalf("server received %d requests, want 0", got)
		}
	})

	t.Run("config key without cert is ignored", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "key-only-config-ok")
		})
		defer server.Close()

		dir := t.TempDir()
		keyPath := writeTempPEM(t, dir, "client.key", "RSA PRIVATE KEY", []byte("fake"))
		configPath := filepath.Join(dir, "config")
		if err := os.WriteFile(configPath, []byte("format = off\nkey = "+keyPath+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runFetch(t, fetchPath, "--config", configPath, server.URL)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "key-only-config-ok")
	})

	t.Run("config min-tls does not override cli tls alias", func(t *testing.T) {
		t.Parallel()
		var requests atomic.Int32
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			io.WriteString(w, "unexpected")
		})
		defer server.Close()

		configPath := filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(configPath, []byte("min-tls = 1.2\nmax-tls = 1.2\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runFetch(t, fetchPath, "--config", configPath, "--tls", "1.3", server.URL)
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "min-tls must be less than or equal to max-tls")
		if got := requests.Load(); got != 0 {
			t.Fatalf("server received %d requests, want 0", got)
		}
	})

	t.Run("config source precedence from-curl insecure", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "curl-insecure-config-ok")
		}))
		defer server.Close()

		configPath := filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(configPath, []byte("format = off\ninsecure = false\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runFetch(t, fetchPath, "--config", configPath, "--from-curl", fmt.Sprintf("curl -k %s", server.URL))
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "curl-insecure-config-ok")
	})

	t.Run("config invalid proxy preserves file context", func(t *testing.T) {
		t.Parallel()
		configPath := filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(configPath, []byte("proxy = :bad\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runFetch(t, fetchPath, "--config", configPath, "http://example.com")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "config file")
		assertBufContains(t, res.stderr, "line 1")
		assertBufContains(t, res.stderr, "invalid value ':bad' for option 'proxy'")
	})

	t.Run("certificate validation failure suggests insecure and is not retried", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "insecure-ok")
		}))
		defer server.Close()

		res := runFetch(t, fetchPath, "--retry", "2", "--retry-delay", fastRetryDelay, server.URL)
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "certificate")
		assertBufContains(t, res.stderr, "If you absolutely trust the server, try '")
		assertBufContains(t, res.stderr, "--insecure")
		assertBufNotContains(t, res.stderr, "retry: attempt")

		res = runFetch(t, fetchPath, "--insecure", server.URL)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "insecure-ok")
	})

	t.Run("default config search", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			if query.Get("default") != "1" || r.Header.Get("X-Default") != "yes" {
				http.Error(w, "default config was not applied", http.StatusBadRequest)
				return
			}
			io.WriteString(w, "default")
		})
		defer server.Close()

		dir := t.TempDir()
		xdgHome := filepath.Join(dir, "xdg")
		configDir := filepath.Join(xdgHome, "fetch")
		if err := os.MkdirAll(configDir, 0o700); err != nil {
			t.Fatal(err)
		}
		config := "format = off\nheader = X-Default: yes\nquery = default=1\n"
		if err := os.WriteFile(filepath.Join(configDir, "config"), []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}

		env := []string{
			"XDG_CONFIG_HOME=" + xdgHome,
			"HOME=" + filepath.Join(dir, "home"),
		}
		res := runFetchOpts(t, fetchPath, fetchOpts{env: env}, server.URL)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "default")
	})

	t.Run("metadata commands use best-effort config", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(path, []byte("format = nope\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runFetch(t, fetchPath, "--config", path, "--help")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufContains(t, res.stdout, "Usage")

		res = runFetch(t, fetchPath, "--config", path, "--version")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufContains(t, res.stdout, "fetch ")

		res = runFetch(t, fetchPath, "--config", path, "--buildinfo")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufContains(t, res.stdout, "{\n")
		assertBufContains(t, res.stdout, `"fetch"`)
		assertBufContains(t, res.stdout, `"settings"`)
		assertBufContains(t, res.stdout, `"deps"`)

		path = filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(path, []byte("color = on\nformat = off\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		res = runFetch(t, fetchPath, "--config", path, "--help")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufContains(t, res.stdout, "\x1b[")

		res = runFetch(t, fetchPath, "--config", path, "--buildinfo")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufContains(t, res.stdout, `"fetch"`)
		assertBufNotContains(t, res.stdout, "\n")

		path = filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(path, []byte("color = on\nformat = on\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		res = runFetch(t, fetchPath, "--config", path, "--buildinfo")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufContains(t, res.stdout, "{\n")
		assertBufContains(t, res.stdout, "\x1b[")
	})

	t.Run("aws-sigv4 auth", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
				w.WriteHeader(400)
				return
			}
			date := r.Header.Get("X-Amz-Date")
			if date == "" {
				w.WriteHeader(400)
				return
			}
			amzSha := r.Header.Get("X-Amz-Content-Sha256")
			w.WriteHeader(200)
			io.WriteString(w, amzSha)
		})
		defer server.Close()

		awsEnv := []string{"AWS_ACCESS_KEY_ID=1234", "AWS_SECRET_ACCESS_KEY=5678"}

		// No request body.
		res := runFetchOpts(t, fetchPath, fetchOpts{env: awsEnv}, server.URL, "--aws-sigv4", "us-east-1/s3")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

		// Direct request body.
		res = runFetchOpts(t, fetchPath, fetchOpts{env: awsEnv}, server.URL, "--aws-sigv4=us-east-1/s3", "-d", "data")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7")

		// Body from file.
		temp := createTempFile(t, "data")
		defer os.Remove(temp)
		res = runFetchOpts(t, fetchPath, fetchOpts{env: awsEnv}, server.URL, "--aws-sigv4=us-east-1/s3", "-d", "@"+temp)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7")

		// Body from stdin.
		res = runFetchOpts(t, fetchPath, fetchOpts{stdin: "data", env: awsEnv}, server.URL, "--aws-sigv4=us-east-1/s3", "-d", "@-")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "UNSIGNED-PAYLOAD")
	})

	t.Run("basic auth", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.WriteHeader(400)
				return
			}
			auth, ok := strings.CutPrefix(auth, "Basic ")
			if !ok {
				w.WriteHeader(400)
				return
			}
			raw, err := base64.StdEncoding.DecodeString(auth)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			user, pass, ok := strings.Cut(string(raw), ":")
			if !ok || user != "user" || pass != "pass" {
				w.WriteHeader(400)
				return
			}
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--basic", "user:pass")
		assertExitCode(t, 0, res)
	})

	t.Run("basic auth invalid format", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "http://example.com", "--basic", "nocolon")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "invalid value 'nocolon' for option '--basic': format must be <USERNAME:PASSWORD>")
	})

	t.Run("bearer auth", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.WriteHeader(400)
				return
			}
			auth, ok := strings.CutPrefix(auth, "Bearer ")
			if !ok {
				w.WriteHeader(400)
				return
			}
			if auth != "token" {
				w.WriteHeader(400)
				return
			}
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--bearer", "token")
		assertExitCode(t, 0, res)
	})

	t.Run("digest auth", func(t *testing.T) {
		t.Parallel()
		var challenged bool
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5"`)
				w.WriteHeader(http.StatusUnauthorized)
				challenged = true
				return
			}
			if !strings.HasPrefix(auth, "Digest ") {
				w.WriteHeader(400)
				return
			}
			// Parse the response from the client.
			params := parseDigestAuthParams(auth[len("Digest "):])
			if params["username"] != "user" || params["realm"] != "test" {
				w.WriteHeader(400)
				return
			}
			// Verify the response hash.
			ha1 := hashMD5("user:test:pass")
			ha2 := hashMD5(r.Method + ":" + params["uri"])
			var expected string
			if params["qop"] == "auth" {
				expected = hashMD5(ha1 + ":abc123:" + params["nc"] + ":" + params["cnonce"] + ":auth:" + ha2)
			} else {
				expected = hashMD5(ha1 + ":abc123:" + ha2)
			}
			if params["response"] != expected {
				w.WriteHeader(400)
				return
			}
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--digest", "user:pass")
		assertExitCode(t, 0, res)
		if !challenged {
			t.Fatal("server did not send digest challenge")
		}
	})

	t.Run("digest auth with body", func(t *testing.T) {
		t.Parallel()
		var challenged bool
		var body string
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5"`)
				w.WriteHeader(http.StatusUnauthorized)
				challenged = true
				return
			}
			if !strings.HasPrefix(auth, "Digest ") {
				w.WriteHeader(400)
				return
			}
			// Parse the response from the client.
			params := parseDigestAuthParams(auth[len("Digest "):])
			if params["username"] != "user" || params["realm"] != "test" {
				w.WriteHeader(400)
				return
			}
			// Verify the response hash.
			ha1 := hashMD5("user:test:pass")
			ha2 := hashMD5(r.Method + ":" + params["uri"])
			var expected string
			if params["qop"] == "auth" {
				expected = hashMD5(ha1 + ":abc123:" + params["nc"] + ":" + params["cnonce"] + ":auth:" + ha2)
			} else {
				expected = hashMD5(ha1 + ":abc123:" + ha2)
			}
			if params["response"] != expected {
				w.WriteHeader(400)
				return
			}
			var buf bytes.Buffer
			buf.ReadFrom(r.Body)
			body = buf.String()
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--digest", "user:pass", "--data", "hello=world")
		assertExitCode(t, 0, res)
		if !challenged {
			t.Fatal("server did not send digest challenge")
		}
		if body != "hello=world" {
			t.Fatalf("unexpected body: %q", body)
		}
	})

	t.Run("digest auth after 303 redirect uses challenged request", func(t *testing.T) {
		t.Parallel()
		var startHits, protectedHits int
		var protectedMethod, protectedBody, digestURI string
		var server *httptest.Server
		server = startServer(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/start":
				startHits++
				http.Redirect(w, r, server.URL+"/protected?token=1", http.StatusSeeOther)
			case "/protected":
				protectedHits++
				auth := r.Header.Get("Authorization")
				if auth == "" {
					w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if !strings.HasPrefix(auth, "Digest ") {
					w.WriteHeader(400)
					return
				}
				params := parseDigestAuthParams(auth[len("Digest "):])
				if params["username"] != "user" || params["realm"] != "test" {
					w.WriteHeader(400)
					return
				}
				protectedMethod = r.Method
				var buf bytes.Buffer
				buf.ReadFrom(r.Body)
				protectedBody = buf.String()
				digestURI = params["uri"]
				if digestURI != "/protected?token=1" {
					w.WriteHeader(400)
					return
				}
				ha1 := hashMD5("user:test:pass")
				ha2 := hashMD5(r.Method + ":" + params["uri"])
				expected := hashMD5(ha1 + ":abc123:" + params["nc"] + ":" + params["cnonce"] + ":auth:" + ha2)
				if params["response"] != expected {
					w.WriteHeader(400)
					return
				}
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL+"/start", "--digest", "user:pass", "--data", "payload")
		assertExitCode(t, 0, res)
		if startHits != 1 {
			t.Fatalf("start hits = %d, want 1", startHits)
		}
		if protectedHits != 2 {
			t.Fatalf("protected hits = %d, want 2", protectedHits)
		}
		if protectedMethod != http.MethodGet {
			t.Fatalf("protected retry method = %s, want GET", protectedMethod)
		}
		if protectedBody != "" {
			t.Fatalf("protected retry body = %q, want empty", protectedBody)
		}
		if digestURI != "/protected?token=1" {
			t.Fatalf("digest uri = %q, want /protected?token=1", digestURI)
		}
	})

	t.Run("digest auth from curl", func(t *testing.T) {
		t.Parallel()
		var challenged bool
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5"`)
				w.WriteHeader(http.StatusUnauthorized)
				challenged = true
				return
			}
			if !strings.HasPrefix(auth, "Digest ") {
				w.WriteHeader(400)
				return
			}
			params := parseDigestAuthParams(auth[len("Digest "):])
			if params["username"] != "user" || params["realm"] != "test" {
				w.WriteHeader(400)
				return
			}
			ha1 := hashMD5("user:test:pass")
			ha2 := hashMD5(r.Method + ":" + params["uri"])
			var expected string
			if params["qop"] == "auth" {
				expected = hashMD5(ha1 + ":abc123:" + params["nc"] + ":" + params["cnonce"] + ":auth:" + ha2)
			} else {
				expected = hashMD5(ha1 + ":abc123:" + ha2)
			}
			if params["response"] != expected {
				w.WriteHeader(400)
				return
			}
		})
		defer server.Close()

		res := runFetch(t, fetchPath, "--from-curl", fmt.Sprintf("curl --digest -u user:pass %s", server.URL))
		assertExitCode(t, 0, res)
		if !challenged {
			t.Fatal("server did not send digest challenge")
		}
	})

	t.Run("data", func(t *testing.T) {
		t.Parallel()
		type requestData struct {
			body          string
			headers       http.Header
			contentLength int64
		}
		chReq := make(chan requestData, 1)
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			var buf bytes.Buffer
			buf.ReadFrom(r.Body)
			chReq <- requestData{
				body:          buf.String(),
				headers:       r.Header,
				contentLength: r.ContentLength,
			}
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--data", "hello")
		assertExitCode(t, 0, res)
		req := <-chReq
		if req.body != "hello" {
			t.Fatalf("unexpected body: %s", req.body)
		}
		if h := req.headers.Get("Content-Type"); h != "text/plain; charset=utf-8" {
			t.Fatalf("unexpected content-type: %s", h)
		}

		res = runFetch(t, fetchPath, server.URL, "--json", `{"key":"val"}`)
		assertExitCode(t, 0, res)
		req = <-chReq
		if req.body != `{"key":"val"}` {
			t.Fatalf("unexpected body: %s", req.body)
		}
		if h := req.headers.Get("Content-Type"); h != "application/json" {
			t.Fatalf("unexpected content-type: %s", h)
		}

		res = runFetch(t, fetchPath, server.URL, "--xml", `<Tag></Tag>`)
		assertExitCode(t, 0, res)
		req = <-chReq
		if req.body != `<Tag></Tag>` {
			t.Fatalf("unexpected body: %s", req.body)
		}
		if h := req.headers.Get("Content-Type"); h != "application/xml" {
			t.Fatalf("unexpected content-type: %s", h)
		}

		const fileContent = "temp file data"
		tempFile := createTempFile(t, fileContent)
		defer os.Remove(tempFile)
		res = runFetch(t, fetchPath, server.URL, "--data", "@"+tempFile)
		assertExitCode(t, 0, res)
		req = <-chReq
		if req.body != "temp file data" {
			t.Fatalf("unexpected body: %s", req.body)
		}
		if h := req.headers.Get("Content-Type"); h != "text/plain; charset=utf-8" {
			t.Fatalf("unexpected file content-type: %s", h)
		}
		// Files should include content-length.
		if req.contentLength != int64(len(fileContent)) {
			t.Fatalf("unexpected content-length: %d", req.contentLength)
		}

	})

	t.Run("edit request body", func(t *testing.T) {
		t.Parallel()
		type requestData struct {
			body        string
			contentType string
		}
		chReq := make(chan requestData, 1)
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			var buf bytes.Buffer
			buf.ReadFrom(r.Body)
			chReq <- requestData{
				body:        buf.String(),
				contentType: r.Header.Get("Content-Type"),
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		env := []string{
			"VISUAL=",
			"EDITOR=" + os.Args[0],
			"FETCH_INTEGRATION_FAKE_EDITOR=1",
			`FETCH_INTEGRATION_FAKE_EDITOR_BODY={"edited":true}`,
		}
		res := runFetchOpts(t, fetchPath, fetchOpts{env: env}, server.URL, "--edit", "--json", `{"template":true}`)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "HTTP/1.1 200 OK")
		assertBufEquals(t, res.stdout, "ok")
		req := <-chReq
		if req.body != `{"edited":true}` {
			t.Fatalf("body = %q, want edited JSON body", req.body)
		}
		if req.contentType != "application/json" {
			t.Fatalf("content-type = %q, want application/json", req.contentType)
		}

		res = runFetchOpts(t, fetchPath, fetchOpts{env: []string{
			"VISUAL=",
			"EDITOR=" + os.Args[0],
			"FETCH_INTEGRATION_FAKE_EDITOR=1",
			"FETCH_INTEGRATION_FAKE_EDITOR_BODY=",
		}}, server.URL, "--edit", "--data", "template")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "aborting request due to empty request body after editing")
	})

	t.Run("request construction", func(t *testing.T) {
		t.Parallel()
		type requestData struct {
			method      string
			rawQuery    string
			contentType string
			custom      string
			body        string
		}
		chReq := make(chan requestData, 1)
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			var buf bytes.Buffer
			buf.ReadFrom(r.Body)
			chReq <- requestData{
				method:      r.Method,
				rawQuery:    r.URL.RawQuery,
				contentType: r.Header.Get("Content-Type"),
				custom:      r.Header.Get("X-Custom"),
				body:        buf.String(),
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		dir := t.TempDir()
		payload := filepath.Join(dir, "payload.json")
		if err := os.WriteFile(payload, []byte(`{"ok":true}`), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runFetch(t, fetchPath,
			server.URL+"?z=old",
			"--method", "PUT",
			"-H", "X-Custom: value",
			"-q", "a=one",
			"-q", "z=two",
			"--data", "@"+payload,
		)
		assertExitCode(t, 0, res)
		req := <-chReq
		if req.method != "PUT" {
			t.Fatalf("method = %q, want PUT", req.method)
		}
		if req.rawQuery != "a=one&z=old&z=two" {
			t.Fatalf("raw query = %q, want sorted Go query encoding", req.rawQuery)
		}
		if req.contentType != "application/json" {
			t.Fatalf("content-type = %q, want application/json", req.contentType)
		}
		if req.custom != "value" {
			t.Fatalf("X-Custom = %q, want value", req.custom)
		}
		if req.body != `{"ok":true}` {
			t.Fatalf("body = %q, want JSON payload", req.body)
		}

		res = runFetch(t, fetchPath, "-H", ": value", server.URL)
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "invalid value ': value' for option '--header'")
	})

	t.Run("host header", func(t *testing.T) {
		t.Parallel()
		chHost := make(chan string, 1)
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			chHost <- r.Host
		})
		defer server.Close()

		res := runFetch(t, fetchPath, "-H", "Host: vhost.example", server.URL)
		assertExitCode(t, 0, res)
		if host := <-chHost; host != "vhost.example" {
			t.Fatalf("unexpected host: got %q, want %q", host, "vhost.example")
		}
	})

	t.Run("dns over https", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/dns-query" {
				io.WriteString(w, `{"Status":0,"Answer":[{"type":1,"data":"127.0.0.1"}]}`)
				return
			}
			if r.URL.Path == "/dns-query-nxdomain" {
				io.WriteString(w, `{"Status":3}`)
				return
			}
			w.WriteHeader(204)
		})
		defer server.Close()

		_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
		if err != nil {
			t.Fatalf("unable to split host and port from server url: %s", err.Error())
		}
		urlStr := "http://localhost:" + port

		res := runFetch(t, fetchPath, urlStr, "--dns-server", server.URL+"/dns-query")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "204 No Content")

		res = runFetch(t, fetchPath, urlStr, "--dns-server", server.URL+"/dns-query-nxdomain")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "no such host")
		assertBufNotContains(t, res.stderr, "For more information")
	})

	t.Run("udp dns server", func(t *testing.T) {
		t.Parallel()
		var wantHost string
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != wantHost {
				t.Errorf("Host = %q, want %q", r.Host, wantHost)
			}
			io.WriteString(w, "udp dns ok")
		})
		defer server.Close()

		_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
		if err != nil {
			t.Fatalf("unable to split host and port from server url: %s", err.Error())
		}
		wantHost = "fetch-dns.test:" + port
		dnsAddr := startUDPDNSServer(t, "fetch-dns.test.", net.ParseIP("127.0.0.1"))

		res := runFetch(t, fetchPath, "--dns-server", dnsAddr, "http://fetch-dns.test:"+port)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "udp dns ok")
	})

	t.Run("inspect dns", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/dns-query" {
				http.NotFound(w, r)
				return
			}
			switch r.URL.Query().Get("type") {
			case "A":
				io.WriteString(w, `{"Status":0,"Answer":[{"type":5,"data":"alias.example.com.","TTL":120},{"type":1,"data":"192.0.2.1","TTL":60}]}`)
			case "AAAA":
				io.WriteString(w, `{"Status":0,"Answer":[{"type":28,"data":"2001:db8::1","TTL":300}]}`)
			case "TXT":
				io.WriteString(w, `{"Status":0,"Answer":[{"type":16,"data":"v=spf1 -all","TTL":180}]}`)
			default:
				io.WriteString(w, `{"Status":0}`)
			}
		})
		defer server.Close()

		res := runFetch(t, fetchPath, "--inspect-dns", "--dns-server", server.URL+"/dns-query", "https://example.com")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "DNS lookup: example.com")
		assertBufContains(t, res.stderr, "Resolver: "+server.URL+"/dns-query")
		assertBufContains(t, res.stderr, "A\n")
		assertBufContains(t, res.stderr, "192.0.2.1 (TTL 1m)")
		assertBufContains(t, res.stderr, "AAAA\n")
		assertBufContains(t, res.stderr, "2001:db8::1 (TTL 5m)")
		assertBufContains(t, res.stderr, "alias.example.com. (TTL 2m)")
		assertBufContains(t, res.stderr, "v=spf1 -all (TTL 3m)")
		assertBufContains(t, res.stderr, "Addresses: 2")

		res = runFetch(t, fetchPath, "--inspect-dns", "--dns-server", server.URL+"/dns-query", "--color", "on", "https://example.com")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "\x1b[2m* \x1b[0m\x1b[1m\x1b[36mDNS lookup\x1b[0m")
		assertBufContains(t, res.stderr, "\x1b[3m"+server.URL+"/dns-query\x1b[0m")
		assertBufContains(t, res.stderr, "\x1b[32m192.0.2.1\x1b[0m")
		assertBufContains(t, res.stderr, "\x1b[2m(TTL 1m)\x1b[0m")
	})

	t.Run("proxy", func(t *testing.T) {
		t.Parallel()
		proxy := startServer(func(w http.ResponseWriter, r *http.Request) {
			if !r.URL.IsAbs() {
				http.Error(w, "request URL was not absolute-form", http.StatusBadRequest)
				return
			}
			if r.URL.Scheme != "http" || r.URL.Host != "target.example" || r.URL.Path != "/via-proxy" {
				http.Error(w, "unexpected proxied URL: "+r.URL.String(), http.StatusBadRequest)
				return
			}
			if r.Header.Get("X-Proxy-Test") != "yes" {
				http.Error(w, "missing proxied header", http.StatusBadRequest)
				return
			}
			io.WriteString(w, "proxied "+r.URL.String())
		})
		defer proxy.Close()

		res := runFetch(t, fetchPath,
			"--proxy", proxy.URL,
			"--format", "off",
			"-H", "X-Proxy-Test: yes",
			"http://target.example/via-proxy?x=1",
		)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "proxied http://target.example/via-proxy?x=1")
	})

	t.Run("proxy from config", func(t *testing.T) {
		t.Parallel()
		proxy := startServer(func(w http.ResponseWriter, r *http.Request) {
			if !r.URL.IsAbs() || r.URL.Host != "config-proxy.example" {
				http.Error(w, "unexpected proxied URL: "+r.URL.String(), http.StatusBadRequest)
				return
			}
			io.WriteString(w, "config proxy")
		})
		defer proxy.Close()

		path := filepath.Join(t.TempDir(), "config")
		config := "format = off\nproxy = " + proxy.URL + "\n"
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}

		res := runFetch(t, fetchPath, "--config", path, "http://config-proxy.example/from-config")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "config proxy")
	})

	t.Run("proxy from environment", func(t *testing.T) {
		t.Parallel()
		proxy := startServer(func(w http.ResponseWriter, r *http.Request) {
			if !r.URL.IsAbs() || r.URL.Host != "env-proxy.example" {
				http.Error(w, "unexpected proxied URL: "+r.URL.String(), http.StatusBadRequest)
				return
			}
			io.WriteString(w, "environment proxy")
		})
		defer proxy.Close()

		env := []string{
			"HTTP_PROXY=" + proxy.URL,
			"http_proxy=" + proxy.URL,
			"HTTPS_PROXY=",
			"https_proxy=",
			"ALL_PROXY=",
			"all_proxy=",
			"NO_PROXY=",
			"no_proxy=",
			"REQUEST_METHOD=",
		}
		res := runFetchOpts(t, fetchPath, fetchOpts{env: env}, "--format", "off", "http://env-proxy.example/from-env")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "environment proxy")
	})

	t.Run("proxy from curl", func(t *testing.T) {
		t.Parallel()
		proxy := startServer(func(w http.ResponseWriter, r *http.Request) {
			if !r.URL.IsAbs() || r.URL.Host != "curl-proxy.example" {
				http.Error(w, "unexpected proxied URL: "+r.URL.String(), http.StatusBadRequest)
				return
			}
			io.WriteString(w, "curl proxy")
		})
		defer proxy.Close()

		cmd := fmt.Sprintf("curl --proxy %s http://curl-proxy.example/from-curl", proxy.URL)
		res := runFetch(t, fetchPath, "--format", "off", "--from-curl", cmd)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "curl proxy")
	})

	t.Run("socks proxy", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/via-socks" && r.URL.Path != "/from-curl-socks" {
				http.Error(w, "unexpected path", http.StatusBadRequest)
				return
			}
			io.WriteString(w, "socks "+r.URL.Path)
		})
		defer server.Close()

		targetAddr := strings.TrimPrefix(server.URL, "http://")
		proxyURL, seen := startSOCKS5Proxy(t, targetAddr)

		res := runFetch(t, fetchPath, "--proxy", proxyURL, "--format", "off", server.URL+"/via-socks")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "socks /via-socks")
		assertSOCKSProxyConnected(t, seen, targetAddr)

		cmd := fmt.Sprintf("curl --proxy %s --silent %s/from-curl-socks", proxyURL, server.URL)
		res = runFetch(t, fetchPath, "--from-curl", cmd)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "socks /from-curl-socks")
		assertSOCKSProxyConnected(t, seen, targetAddr)
	})

	t.Run("proxy rejects HTTP2", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath,
			"--proxy", "http://proxy.example:8080",
			"--http", "2",
			"https://example.com",
		)
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "a proxy can only be used with HTTP/1.1")
	})

	t.Run("form", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			var buf bytes.Buffer
			buf.ReadFrom(r.Body)
			q, _ := url.ParseQuery(buf.String())
			if len(q) != 2 {
				w.WriteHeader(400)
				return
			}
			if q.Get("key1") != "val1" {
				w.WriteHeader(400)
				return
			}
			if q.Get("key2") != "val2" {
				w.WriteHeader(400)
				return
			}
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "-f", "key1=val1", "-f", "key2=val2")
		assertExitCode(t, 0, res)
	})

	t.Run("http version", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--http", "1")
		assertExitCode(t, 0, res)

		res = runFetch(t, fetchPath, server.URL, "--http", "2")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "http2:")
	})

	t.Run("http3 request", func(t *testing.T) {
		t.Parallel()

		type requestData struct {
			method   string
			path     string
			rawQuery string
			headers  http.Header
			body     string
			proto    string
		}
		reqCh := make(chan requestData, 1)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var buf bytes.Buffer
			buf.ReadFrom(r.Body)
			reqCh <- requestData{
				method:   r.Method,
				path:     r.URL.Path,
				rawQuery: r.URL.RawQuery,
				headers:  r.Header.Clone(),
				body:     buf.String(),
				proto:    r.Proto,
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, "h3 ok")
		})
		server3 := startHTTP3Server(t, handler)

		res := runFetchOpts(t, fetchPath, fetchOpts{env: noProxyEnv()},
			server3.url+"/h3?existing=1",
			"--http", "3",
			"--ca-cert", server3.caCertPath,
			"--method", "PUT",
			"-H", "X-H3: yes",
			"-q", "cli=1",
			"-d", "payload",
		)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "h3 ok")
		assertBufContains(t, res.stderr, "HTTP/3.0 201 Created")

		req := <-reqCh
		if req.proto != "HTTP/3.0" {
			t.Fatalf("proto = %q, want HTTP/3.0", req.proto)
		}
		if req.method != "PUT" {
			t.Fatalf("method = %q, want PUT", req.method)
		}
		if req.path != "/h3" {
			t.Fatalf("path = %q, want /h3", req.path)
		}
		if req.rawQuery != "cli=1&existing=1" {
			t.Fatalf("raw query = %q, want Go-style sorted query", req.rawQuery)
		}
		if req.headers.Get("X-H3") != "yes" {
			t.Fatalf("X-H3 = %q, want yes", req.headers.Get("X-H3"))
		}
		if req.body != "payload" {
			t.Fatalf("body = %q, want payload", req.body)
		}

		res = runFetch(t, fetchPath, "http://example.com", "--http", "3")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "http3: unsupported protocol scheme: http")
	})

	t.Run("http3 redirect", func(t *testing.T) {
		t.Parallel()

		type requestData struct {
			method string
			path   string
			body   string
			proto  string
		}
		reqCh := make(chan requestData, 2)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			reqCh <- requestData{
				method: r.Method,
				path:   r.URL.Path,
				body:   string(body),
				proto:  r.Proto,
			}
			if r.URL.Path == "/start" {
				w.Header().Set("Location", "/final")
				w.WriteHeader(http.StatusTemporaryRedirect)
				return
			}
			if r.URL.Path != "/final" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method != "POST" || string(body) != "redirect-body" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "method=%s body=%q", r.Method, string(body))
				return
			}
			io.WriteString(w, "h3 redirected")
		})
		server3 := startHTTP3Server(t, handler)

		res := runFetchOpts(t, fetchPath, fetchOpts{env: noProxyEnv()},
			server3.url+"/start",
			"--http", "3",
			"--ca-cert", server3.caCertPath,
			"--method", "POST",
			"-d", "redirect-body",
		)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "h3 redirected")
		assertBufContains(t, res.stderr, "HTTP/3.0 200 OK")

		first := receiveHTTP3Request(t, reqCh)
		second := receiveHTTP3Request(t, reqCh)
		if first.path != "/start" || second.path != "/final" {
			t.Fatalf("redirect paths = %q then %q, want /start then /final", first.path, second.path)
		}
		for _, req := range []requestData{first, second} {
			if req.proto != "HTTP/3.0" {
				t.Fatalf("%s proto = %q, want HTTP/3.0", req.path, req.proto)
			}
			if req.method != "POST" {
				t.Fatalf("%s method = %q, want POST", req.path, req.method)
			}
			if req.body != "redirect-body" {
				t.Fatalf("%s body = %q, want redirect-body", req.path, req.body)
			}
		}
	})

	t.Run("http3 retry with request body", func(t *testing.T) {
		t.Parallel()

		var count atomic.Int64
		type requestData struct {
			body  string
			proto string
		}
		reqCh := make(chan requestData, 2)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			reqCh <- requestData{
				body:  string(body),
				proto: r.Proto,
			}
			if count.Add(1) <= 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			io.WriteString(w, "h3 retry ok")
		})
		server3 := startHTTP3Server(t, handler)

		res := runFetchOpts(t, fetchPath, fetchOpts{env: noProxyEnv()},
			server3.url+"/retry",
			"--http", "3",
			"--ca-cert", server3.caCertPath,
			"--retry", "1",
			"--retry-delay", fastRetryDelay,
			"-d", "retry-body",
		)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "h3 retry ok")
		assertBufContains(t, res.stderr, "retry")
		if count.Load() != 2 {
			t.Fatalf("expected 2 requests, got %d", count.Load())
		}
		for i := 0; i < 2; i++ {
			req := receiveHTTP3Request(t, reqCh)
			if req.proto != "HTTP/3.0" {
				t.Fatalf("attempt %d proto = %q, want HTTP/3.0", i+1, req.proto)
			}
			if req.body != "retry-body" {
				t.Fatalf("attempt %d body = %q, want retry-body", i+1, req.body)
			}
		}
	})

	t.Run("http3 session cookies persist", func(t *testing.T) {
		t.Parallel()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Proto != "HTTP/3.0" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "proto=%s", r.Proto)
				return
			}
			switch r.URL.Path {
			case "/login":
				http.SetCookie(w, &http.Cookie{
					Name:  "h3_session",
					Value: "abc123",
					Path:  "/",
				})
				io.WriteString(w, "logged in")
			case "/dashboard":
				cookie, err := r.Cookie("h3_session")
				if err != nil || cookie.Value != "abc123" {
					w.WriteHeader(http.StatusUnauthorized)
					io.WriteString(w, "unauthorized")
					return
				}
				io.WriteString(w, "welcome h3")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})
		server3 := startHTTP3Server(t, handler)
		sessEnv := noProxyEnv("FETCH_INTERNAL_SESSIONS_DIR=" + t.TempDir())

		res := runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv},
			server3.url+"/login",
			"--http", "3",
			"--ca-cert", server3.caCertPath,
			"--session", "h3-integ",
		)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "logged in")

		res = runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv},
			server3.url+"/dashboard",
			"--http", "3",
			"--ca-cert", server3.caCertPath,
			"--session", "h3-integ",
		)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "welcome h3")
	})

	t.Run("http3 proxy rejection", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath,
			"--proxy", "http://proxy.example:8080",
			"--http", "3",
			"https://example.com",
		)
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "a proxy can only be used with HTTP/1.1")
	})

	t.Run("multipart", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, "cannot parse media type: "+err.Error())
				return
			}
			if mediaType != "multipart/form-data" {
				w.WriteHeader(400)
				io.WriteString(w, "invalid media type: "+mediaType)
				return
			}

			form, err := multipart.NewReader(r.Body, params["boundary"]).ReadForm(1 << 24)
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, "cannot read form: "+err.Error())
				return
			}

			if len(form.Value) != 1 || form.Value["key1"][0] != "val1" {
				w.WriteHeader(400)
				io.WriteString(w, fmt.Sprintf("invalid form values: %+v", form.Value))
				return
			}
			if len(form.File) != 1 {
				w.WriteHeader(400)
				io.WriteString(w, fmt.Sprintf("invalid form files: %+v", form.File))
				return
			}
			header := form.File["file1"][0]
			if ct := header.Header.Get("Content-Type"); ct != "image/jpeg" {
				w.WriteHeader(400)
				io.WriteString(w, fmt.Sprintf("invalid content-type: %q", ct))
				return
			}
			file, err := header.Open()
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, "cannot open form file: "+err.Error())
				return
			}

			var buf bytes.Buffer
			buf.ReadFrom(file)
			if buf.String() != "\xFF\xD8\xFF" {
				w.WriteHeader(400)
				io.WriteString(w, "invalid file content: "+buf.String())
				return
			}
		})
		defer server.Close()

		tempFile := createTempFile(t, "\xFF\xD8\xFF") // JPEG signature.
		defer os.Remove(tempFile)
		res := runFetch(t, fetchPath, server.URL, "-F", "key1=val1", "-F", "file1=@"+tempFile)
		assertExitCode(t, 0, res)
	})

	t.Run("multipart 307 redirect", func(t *testing.T) {
		t.Parallel()
		var startHits, finalHits atomic.Int64
		var server *httptest.Server
		server = startServer(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/start":
				startHits.Add(1)
				http.Redirect(w, r, server.URL+"/final", http.StatusTemporaryRedirect)
			case "/final":
				finalHits.Add(1)
				if r.Method != http.MethodPost {
					w.WriteHeader(400)
					io.WriteString(w, "invalid method: "+r.Method)
					return
				}
				mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil {
					w.WriteHeader(400)
					io.WriteString(w, "cannot parse media type: "+err.Error())
					return
				}
				if mediaType != "multipart/form-data" {
					w.WriteHeader(400)
					io.WriteString(w, "invalid media type: "+mediaType)
					return
				}

				form, err := multipart.NewReader(r.Body, params["boundary"]).ReadForm(1 << 24)
				if err != nil {
					w.WriteHeader(400)
					io.WriteString(w, "cannot read form: "+err.Error())
					return
				}
				values := form.Value["key1"]
				if len(form.Value) != 1 || len(values) != 1 || values[0] != "val1" {
					w.WriteHeader(400)
					io.WriteString(w, fmt.Sprintf("invalid form values: %+v", form.Value))
					return
				}
				files := form.File["file1"]
				if len(form.File) != 1 || len(files) != 1 {
					w.WriteHeader(400)
					io.WriteString(w, fmt.Sprintf("invalid form files: %+v", form.File))
					return
				}
				header := files[0]
				if header.Filename != filepath.Base(header.Filename) {
					w.WriteHeader(400)
					io.WriteString(w, "multipart filename includes path: "+header.Filename)
					return
				}
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		})
		defer server.Close()

		tempFile := createTempFile(t, "redirected file")
		defer os.Remove(tempFile)
		res := runFetch(t, fetchPath, server.URL+"/start", "-m", "POST", "-F", "key1=val1", "-F", "file1=@"+tempFile)
		assertExitCode(t, 0, res)
		if got := startHits.Load(); got != 1 {
			t.Fatalf("start hits = %d, want 1", got)
		}
		if got := finalHits.Load(); got != 1 {
			t.Fatalf("final hits = %d, want 1", got)
		}
	})

	t.Run("output", func(t *testing.T) {
		t.Parallel()
		const data = "this is the data"
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		dir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Fatalf("unable to create temp dir: %s", err.Error())
		}
		defer os.RemoveAll(dir)

		// Test writing to an output file.
		path := filepath.Join(dir, "output")
		res := runFetch(t, fetchPath, server.URL, "-o", path)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "Downloaded 16B")
		assertBufContains(t, res.stderr, path)

		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("unable to read from output file: %s", err.Error())
		}
		if string(raw) != data {
			t.Fatalf("unexpected data in output file: %s", raw)
		}

		// Test writing to stdout.
		res = runFetch(t, fetchPath, server.URL, "-o", "-")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, data)

		// Test decoded compressed responses when writing to an output file.
		var compressed bytes.Buffer
		gw := gzip.NewWriter(&compressed)
		if _, err := io.WriteString(gw, data); err != nil {
			t.Fatalf("unable to write gzip body: %s", err.Error())
		}
		if err := gw.Close(); err != nil {
			t.Fatalf("unable to close gzip writer: %s", err.Error())
		}
		gzipServer := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(200)
			w.Write(compressed.Bytes())
		})
		defer gzipServer.Close()

		gzipPath := filepath.Join(dir, "gzip-output")
		res = runFetch(t, fetchPath, gzipServer.URL, "-o", gzipPath)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "Downloaded 16B")

		raw, err = os.ReadFile(gzipPath)
		if err != nil {
			t.Fatalf("unable to read from gzip output file: %s", err.Error())
		}
		if string(raw) != data {
			t.Fatalf("unexpected gzip output file data: %s", raw)
		}

		var zstdCompressed bytes.Buffer
		zw, err := zstd.NewWriter(&zstdCompressed)
		if err != nil {
			t.Fatalf("unable to create zstd writer: %s", err.Error())
		}
		if _, err := io.WriteString(zw, data); err != nil {
			t.Fatalf("unable to write zstd body: %s", err.Error())
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("unable to close zstd writer: %s", err.Error())
		}
		zstdServer := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "zstd")
			w.WriteHeader(200)
			w.Write(zstdCompressed.Bytes())
		})
		defer zstdServer.Close()

		zstdPath := filepath.Join(dir, "zstd-output")
		res = runFetch(t, fetchPath, zstdServer.URL, "-o", zstdPath)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "Downloaded 16B")

		raw, err = os.ReadFile(zstdPath)
		if err != nil {
			t.Fatalf("unable to read from zstd output file: %s", err.Error())
		}
		if string(raw) != data {
			t.Fatalf("unexpected zstd output file data: %s", raw)
		}
	})

	t.Run("output-current-dir", func(t *testing.T) {
		t.Parallel()
		const data = "this is the current dir data"
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		dir := t.TempDir()

		urlStr := server.URL + "/dir/path_to_file.txt"
		res := runFetchOpts(t, fetchPath, fetchOpts{dir: dir}, urlStr, "-O")
		assertExitCode(t, 0, res)

		expPath := filepath.Join(dir, "path_to_file.txt")
		raw, err := os.ReadFile(expPath)
		if err != nil {
			t.Fatalf("unable to read from output file: %s", err.Error())
		}
		if string(raw) != data {
			t.Fatalf("unexpected data in output file: %s", raw)
		}
	})

	t.Run("remote-name ignores content-disposition", func(t *testing.T) {
		t.Parallel()
		const data = "file content"
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Disposition", `attachment; filename="cd-filename.txt"`)
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		dir := t.TempDir()

		// -O should use URL path, NOT Content-Disposition
		urlStr := server.URL + "/url-filename.txt"
		res := runFetchOpts(t, fetchPath, fetchOpts{dir: dir}, urlStr, "-O")
		assertExitCode(t, 0, res)

		// Verify URL-based filename was used
		expPath := filepath.Join(dir, "url-filename.txt")
		raw, err := os.ReadFile(expPath)
		if err != nil {
			t.Fatalf("unable to read from output file: %s", err.Error())
		}
		if string(raw) != data {
			t.Fatalf("unexpected data in output file: %s", raw)
		}

		// Verify Content-Disposition filename was NOT used
		cdPath := filepath.Join(dir, "cd-filename.txt")
		if _, err := os.Stat(cdPath); !os.IsNotExist(err) {
			t.Fatal("Content-Disposition filename should not exist when using -O without -J")
		}
	})

	t.Run("remote-header-name uses content-disposition", func(t *testing.T) {
		t.Parallel()
		const data = "file content"
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Disposition", `attachment; filename="cd-filename.txt"`)
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		dir := t.TempDir()

		// -O -J should use Content-Disposition
		urlStr := server.URL + "/url-filename.txt"
		res := runFetchOpts(t, fetchPath, fetchOpts{dir: dir}, urlStr, "-O", "-J")
		assertExitCode(t, 0, res)

		// Verify Content-Disposition filename was used
		expPath := filepath.Join(dir, "cd-filename.txt")
		raw, err := os.ReadFile(expPath)
		if err != nil {
			t.Fatalf("unable to read from output file: %s", err.Error())
		}
		if string(raw) != data {
			t.Fatalf("unexpected data in output file: %s", raw)
		}
	})

	t.Run("remote-header-name requires remote-name", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "http://example.com", "-J")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "flag '--remote-header-name' requires '--remote-name'")
	})

	t.Run("file exists error", func(t *testing.T) {
		t.Parallel()
		const data = "file content"
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		dir := t.TempDir()

		// Create existing file
		existingPath := filepath.Join(dir, "existing.txt")
		if err := os.WriteFile(existingPath, []byte("old content"), 0644); err != nil {
			t.Fatalf("unable to create existing file: %s", err.Error())
		}

		// Attempt to overwrite without --clobber should fail
		urlStr := server.URL + "/existing.txt"
		res := runFetchOpts(t, fetchPath, fetchOpts{dir: dir}, urlStr, "-O")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "already exists")
		assertBufContains(t, res.stderr, "--clobber")

		// Verify file was not modified
		raw, err := os.ReadFile(existingPath)
		if err != nil {
			t.Fatalf("unable to read from existing file: %s", err.Error())
		}
		if string(raw) != "old content" {
			t.Fatalf("existing file was modified: %s", raw)
		}
	})

	t.Run("direct output file exists error", func(t *testing.T) {
		t.Parallel()
		const data = "new content"
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		dir := t.TempDir()

		existingPath := filepath.Join(dir, "existing.txt")
		if err := os.WriteFile(existingPath, []byte("old content"), 0644); err != nil {
			t.Fatalf("unable to create existing file: %s", err.Error())
		}

		res := runFetch(t, fetchPath, server.URL, "-o", existingPath)
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "already exists")
		assertBufContains(t, res.stderr, "--clobber")

		raw, err := os.ReadFile(existingPath)
		if err != nil {
			t.Fatalf("unable to read from existing file: %s", err.Error())
		}
		if string(raw) != "old content" {
			t.Fatalf("existing file was modified: %s", raw)
		}

		res = runFetch(t, fetchPath, server.URL, "-o", existingPath, "--clobber")
		assertExitCode(t, 0, res)

		raw, err = os.ReadFile(existingPath)
		if err != nil {
			t.Fatalf("unable to read from existing file: %s", err.Error())
		}
		if string(raw) != data {
			t.Fatalf("existing file was not overwritten: %s", raw)
		}
	})

	t.Run("clobber overwrites existing file", func(t *testing.T) {
		t.Parallel()
		const data = "new content"
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		dir := t.TempDir()

		// Create existing file
		existingPath := filepath.Join(dir, "existing.txt")
		if err := os.WriteFile(existingPath, []byte("old content"), 0644); err != nil {
			t.Fatalf("unable to create existing file: %s", err.Error())
		}

		// Overwrite with --clobber should succeed
		urlStr := server.URL + "/existing.txt"
		res := runFetchOpts(t, fetchPath, fetchOpts{dir: dir}, urlStr, "-O", "--clobber")
		assertExitCode(t, 0, res)

		// Verify file was overwritten
		raw, err := os.ReadFile(existingPath)
		if err != nil {
			t.Fatalf("unable to read from existing file: %s", err.Error())
		}
		if string(raw) != data {
			t.Fatalf("existing file was not overwritten: %s", raw)
		}
	})

	t.Run("path traversal blocked in content-disposition", func(t *testing.T) {
		t.Parallel()
		const data = "file content"
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			// Attempt path traversal in Content-Disposition header
			w.Header().Set("Content-Disposition", `attachment; filename="../../../tmp/malicious.txt"`)
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		dir := t.TempDir()

		// -O -J with path traversal in Content-Disposition should sanitize to base name
		urlStr := server.URL + "/fallback.txt"
		res := runFetchOpts(t, fetchPath, fetchOpts{dir: dir}, urlStr, "-O", "-J")
		assertExitCode(t, 0, res)

		// Verify sanitized filename was used (base name of the path)
		expPath := filepath.Join(dir, "malicious.txt")
		raw, err := os.ReadFile(expPath)
		if err != nil {
			t.Fatalf("unable to read from output file: %s", err.Error())
		}
		if string(raw) != data {
			t.Fatalf("unexpected data in output file: %s", raw)
		}

		// Verify path traversal did not work
		badPath := filepath.Join(dir, "..", "..", "..", "tmp", "malicious.txt")
		if _, err := os.Stat(badPath); !os.IsNotExist(err) {
			t.Fatal("path traversal should have been blocked")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
			}
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "-t", "0.0000001")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "request timed out after 100ns")
		assertBufNotContains(t, res.stderr, "For more information")
	})

	t.Run("connect timeout", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--connect-timeout", "5")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("connect timeout invalid", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "http://localhost", "--connect-timeout", "-1")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "connect-timeout")
	})

	t.Run("unix socket", func(t *testing.T) {
		t.Parallel()
		// Verify help output.
		res := runFetch(t, fetchPath, "--help")
		assertExitCode(t, 0, res)
		if runtime.GOOS == "windows" {
			assertBufNotContains(t, res.stdout, "unix")
		} else {
			assertBufContains(t, res.stdout, "unix")
		}

		if runtime.GOOS == "windows" {
			t.Skip("unix sockets not supported")
		}

		sock := filepath.Join(t.TempDir(), "server.sock")

		server, err := startUnixServer(sock, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			io.WriteString(w, "hello")
		})
		if err != nil {
			t.Fatalf("unable to start unix server: %s", err.Error())
		}
		defer server.Close()

		res = runFetch(t, fetchPath, "--unix", sock, "http://unix/")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "hello")
	})

	t.Run("ignore status", func(t *testing.T) {
		t.Parallel()
		var statusCode atomic.Int64
		statusCode.Store(200)
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(int(statusCode.Load()))
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL)
		assertExitCode(t, 0, res)

		statusCode.Store(400)
		res = runFetch(t, fetchPath, server.URL)
		assertExitCode(t, 4, res)
		res = runFetch(t, fetchPath, server.URL, "--ignore-status")
		assertExitCode(t, 0, res)

		statusCode.Store(500)
		res = runFetch(t, fetchPath, server.URL)
		assertExitCode(t, 5, res)
		res = runFetch(t, fetchPath, server.URL, "--ignore-status")
		assertExitCode(t, 0, res)

		statusCode.Store(999)
		res = runFetch(t, fetchPath, server.URL)
		assertExitCode(t, 6, res)
		res = runFetch(t, fetchPath, server.URL, "--ignore-status")
		assertExitCode(t, 0, res)
	})

	t.Run("range request", func(t *testing.T) {
		t.Parallel()
		var expectedRange atomic.Pointer[string]
		expectedRange.Store(new(""))
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			exp := expectedRange.Load()
			if r.Header.Get("Range") != *exp {
				w.WriteHeader(400)
				return
			}
		})
		defer server.Close()

		// Invalid range header.
		res := runFetch(t, fetchPath, server.URL, "--range", "bad")
		assertExitCode(t, 1, res)

		// No range header.
		res = runFetch(t, fetchPath, server.URL)
		assertExitCode(t, 0, res)

		// Range header with no start.
		expectedRange.Store(new("bytes=-1023"))
		res = runFetch(t, fetchPath, server.URL, "--range", "-1023")
		assertExitCode(t, 0, res)

		// Range header with no end.
		expectedRange.Store(new("bytes=1023-"))
		res = runFetch(t, fetchPath, server.URL, "--range", "1023-")
		assertExitCode(t, 0, res)

		// Range header with start and end.
		expectedRange.Store(new("bytes=0-1023"))
		res = runFetch(t, fetchPath, server.URL, "--range", "0-1023")
		assertExitCode(t, 0, res)

		// Multiple ranges.
		expectedRange.Store(new("bytes=0-1023, 2047-3070"))
		res = runFetch(t, fetchPath, server.URL, "-r", "0-1023", "-r", "2047-3070")
		assertExitCode(t, 0, res)
	})

	t.Run("redirects", func(t *testing.T) {
		t.Parallel()
		var empty string
		var urlStr atomic.Pointer[string]
		urlStr.Store(&empty)

		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			if count.Add(-1) < 0 {
				w.WriteHeader(200)
				return
			}

			w.Header().Set("Location", *urlStr.Load())
			w.WriteHeader(301)
		})
		defer server.Close()
		urlStr.Store(&server.URL)

		// Success with no redirects.
		res := runFetch(t, fetchPath, server.URL, "--redirects", "0")
		assertExitCode(t, 0, res)

		// Returns 301 with no redirects.
		count.Store(1)
		res = runFetch(t, fetchPath, server.URL, "--redirects", "0")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "301 Moved Permanently")

		// Returns 200 with redirects.
		count.Store(5)
		res = runFetch(t, fetchPath, server.URL)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "200 OK")

		// Returns an error when max redirects exceeded.
		count.Store(2)
		res = runFetch(t, fetchPath, server.URL, "--redirects", "1")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "exceeded maximum number of redirects")
		assertBufNotContains(t, res.stderr, "For more information")

		// Redirect at -vv shows prefixed request/response for each hop.
		count.Store(1)
		res = runFetch(t, fetchPath, server.URL, "-vv")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "> GET / HTTP/1.1")
		assertBufContains(t, res.stderr, "< HTTP/1.1 301 Moved Permanently")
		assertBufContains(t, res.stderr, "< HTTP/1.1 200 OK")
	})

	t.Run("server sent events", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			const data = ":comment\n\ndata:{\"key\":\"val\"}\n\nevent:ev1\ndata: this is my data\n\n"
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "[message]\n{ \"key\": \"val\" }\n\n[ev1]\nthis is my data\n")
	})

	t.Run("ndjson formatting", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			const data = "{\"b\":1.2300,\"a\":2}\n[true,null]\n"
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "{ \"b\": 1.2300, \"a\": 2 }\n[true, null]\n")
	})

	t.Run("charset-aware json formatting", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=iso-8859-1")
			w.WriteHeader(200)
			w.Write([]byte{'{', '"', 'w', 'o', 'r', 'd', '"', ':', '"', 'c', 'a', 'f', 0xe9, '"', '}'})
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "{\n  \"word\": \"café\"\n}\n")
	})

	t.Run("csv formatting", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			const data = "name,age\nAlice,30\nBob,9"
			w.Header().Set("Content-Type", "text/csv")
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "name   age\nAlice  30\nBob    9\n")
	})

	t.Run("xml formatting", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			const data = `<?xml version="1.0"?><root attr="value"><item>hello</item><empty/></root>`
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "<?xml version=\"1.0\"?>\n<root attr=\"value\">\n  <item>hello</item>\n  <empty></empty>\n</root>\n")
	})

	t.Run("yaml formatting", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			const data = "name: John\nitems:\n  - one\n  - two\n# kept\n"
			w.Header().Set("Content-Type", "application/x-yaml")
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "name: John\nitems:\n  - one\n  - two\n# kept\n")
	})

	t.Run("html formatting", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			const data = `<!DOCTYPE html><html><head><title>Test</title></head><body><div class="container"><h1>Hello</h1><p>Text with <strong>bold</strong></p><br><img src="x.jpg"></div></body></html>`
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, `<!DOCTYPE html>
<html>
  <head>
    <title>Test</title>
  </head>
  <body>
    <div class="container">
      <h1>Hello</h1>
      <p>Text with <strong>bold</strong></p>
      <br>
      <img src="x.jpg">
    </div>
  </body>
</html>
`)
	})

	t.Run("markdown formatting", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			const data = "# Title\n\nSome **bold** text.\n\n- one\n- two\n"
			w.Header().Set("Content-Type", "text/markdown")
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "# Title\n\nSome bold text.\n\n- one\n- two\n")
	})

	t.Run("msgpack formatting", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			data := []byte{
				0x82,
				0xa4, 'k', 'e', 'y', '1',
				0xa4, 'v', 'a', 'l', '1',
				0xa4, 'k', 'e', 'y', '2',
				0xa4, 'v', 'a', 'l', '2',
			}
			w.Header().Set("Content-Type", "application/vnd.msgpack")
			w.WriteHeader(200)
			w.Write(data)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "{\n  \"key1\": \"val1\",\n  \"key2\": \"val2\"\n}\n")
	})

	t.Run("css formatting", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			const data = "body{color:red;margin:0}.container{display:flex}"
			w.Header().Set("Content-Type", "text/css")
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "body {\n  color: red;\n  margin: 0;\n}\n\n.container {\n  display: flex;\n}\n")
	})

	t.Run("image off", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(200)
			io.WriteString(w, "raw image bytes")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on", "--image", "off")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "raw image bytes")

		res = runFetch(t, fetchPath, server.URL, "--image", "bad")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "invalid value 'bad' for option '--image'")
	})

	t.Run("gzip compression", func(t *testing.T) {
		t.Parallel()
		const data = "this is the test data"

		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Accept-Encoding") != "gzip, zstd" {
				w.Write([]byte(data))
				return
			}

			if r.URL.Path == "/chunked" {
				w.Header().Set("Content-Encoding", "aws-chunked, gzip")
			} else {
				w.Header().Set("Content-Encoding", "gzip")
			}

			gw := gzip.NewWriter(w)
			gw.Write([]byte(data))
			gw.Close()
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "-v")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, data)
		assertBufContains(t, res.stderr, "gzip")

		res = runFetch(t, fetchPath, server.URL+"/chunked", "-v")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, data)
		assertBufContains(t, res.stderr, "aws-chunked, gzip")

		res = runFetch(t, fetchPath, server.URL, "-v", "--no-encode")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, data)
		assertBufNotContains(t, res.stderr, "gzip")
	})

	t.Run("zstd compression", func(t *testing.T) {
		t.Parallel()
		const data = "this is the test data"

		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Accept-Encoding") != "gzip, zstd" {
				w.Write([]byte(data))
				return
			}

			if r.URL.Path == "/chunked" {
				w.Header().Set("Content-Encoding", "aws-chunked, zstd")
			} else {
				w.Header().Set("Content-Encoding", "zstd")
			}

			zw, err := zstd.NewWriter(w)
			if err != nil {
				panic(err)
			}
			defer zw.Close()
			zw.Write([]byte(data))
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "-v")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, data)
		assertBufContains(t, res.stderr, "zstd")

		res = runFetch(t, fetchPath, server.URL+"/chunked", "-v")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, data)
		assertBufContains(t, res.stderr, "aws-chunked, zstd")

		res = runFetch(t, fetchPath, server.URL, "-v", "--no-encode")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, data)
		assertBufNotContains(t, res.stderr, "zstd")
	})

	t.Run("protobuf response formatting", func(t *testing.T) {
		t.Parallel()
		// Build a simple protobuf message: field 1 = 123 (varint), field 2 = "hello" (string)
		var protoData []byte
		protoData = protowire.AppendTag(protoData, 1, protowire.VarintType)
		protoData = protowire.AppendVarint(protoData, 123)
		protoData = protowire.AppendTag(protoData, 2, protowire.BytesType)
		protoData = protowire.AppendString(protoData, "hello")

		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/protobuf")
			w.WriteHeader(200)
			w.Write(protoData)
		})
		defer server.Close()

		// Without formatting, output is the raw protobuf.
		res := runFetch(t, fetchPath, server.URL, "--format", "off")
		assertExitCode(t, 0, res)
		if !bytes.Equal(res.stdout.Bytes(), protoData) {
			t.Fatalf("expected raw protobuf data")
		}

		// With formatting, protobuf is parsed and displayed.
		res = runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "1:")
		assertBufContains(t, res.stdout, "123")
		assertBufContains(t, res.stdout, "2:")
		assertBufContains(t, res.stdout, "hello")

		// In gRPC mode, Go uses the method's response descriptor even when a
		// server replies with a plain application/protobuf body instead of a
		// gRPC-framed stream.
		descFile := writeHealthDescriptorSet(t)
		schemaServer := startServer(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/protobuf")
			w.WriteHeader(200)
			w.Write(buildHealthCheckResponse())
		})
		defer schemaServer.Close()

		res = runFetch(t, fetchPath,
			schemaServer.URL+"/grpc.health.v1.Health/Check",
			"--grpc", "--proto-desc", descFile,
			"--http", "1", "--format", "on")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, `"status": "SERVING"`)
		assertBufNotContains(t, res.stdout, "1:")
	})

	t.Run("connect rpc error response", func(t *testing.T) {
		t.Parallel()
		// Simulate a Connect RPC error response.
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			io.WriteString(w, `{"code":"not_found","message":"resource not found"}`)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 4, res) // 4xx status code
		assertBufContains(t, res.stdout, "not_found")
		assertBufContains(t, res.stdout, "resource not found")
	})

	t.Run("grpc response unframing", func(t *testing.T) {
		t.Parallel()
		// Build a gRPC-framed protobuf response.
		var protoData []byte
		protoData = protowire.AppendTag(protoData, 1, protowire.VarintType)
		protoData = protowire.AppendVarint(protoData, 42)
		protoData = protowire.AppendTag(protoData, 2, protowire.BytesType)
		protoData = protowire.AppendString(protoData, "grpc test")

		// gRPC framing: [compressed:1][length:4][data]
		framedData := make([]byte, 5+len(protoData))
		framedData[0] = 0 // not compressed
		binary.BigEndian.PutUint32(framedData[1:5], uint32(len(protoData)))
		copy(framedData[5:], protoData)

		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc+proto")
			w.WriteHeader(200)
			w.Write(framedData)
		})
		defer server.Close()

		// With formatting, gRPC response is unframed and protobuf is parsed.
		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "1:")
		assertBufContains(t, res.stdout, "42")
		assertBufContains(t, res.stdout, "2:")
		assertBufContains(t, res.stdout, "grpc test")
	})

	t.Run("grpc streaming response", func(t *testing.T) {
		t.Parallel()
		// Build 3 separate gRPC-framed protobuf messages.
		makeFrame := func(fieldNum protowire.Number, value string) []byte {
			var protoData []byte
			protoData = protowire.AppendTag(protoData, fieldNum, protowire.BytesType)
			protoData = protowire.AppendString(protoData, value)
			framedData := make([]byte, 5+len(protoData))
			framedData[0] = 0 // not compressed
			binary.BigEndian.PutUint32(framedData[1:5], uint32(len(protoData)))
			copy(framedData[5:], protoData)
			return framedData
		}

		frame1 := makeFrame(1, "message one")
		frame2 := makeFrame(1, "message two")
		frame3 := makeFrame(1, "message three")

		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc+proto")
			w.WriteHeader(200)
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "no flusher", 500)
				return
			}
			w.Write(frame1)
			flusher.Flush()
			w.Write(frame2)
			flusher.Flush()
			w.Write(frame3)
			flusher.Flush()
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "message one")
		assertBufContains(t, res.stdout, "message two")
		assertBufContains(t, res.stdout, "message three")
	})

	t.Run("grpc streaming error status", func(t *testing.T) {
		t.Parallel()
		// Build a single gRPC-framed protobuf message.
		var protoData []byte
		protoData = protowire.AppendTag(protoData, 1, protowire.BytesType)
		protoData = protowire.AppendString(protoData, "partial data")
		framedData := make([]byte, 5+len(protoData))
		framedData[0] = 0
		binary.BigEndian.PutUint32(framedData[1:5], uint32(len(protoData)))
		copy(framedData[5:], protoData)

		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc+proto")
			w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
			w.WriteHeader(200)
			w.Write(framedData)
			w.(http.Flusher).Flush()
			// Set trailers after body.
			w.Header().Set("Grpc-Status", "13")      // INTERNAL
			w.Header().Set("Grpc-Message", "oh no!") // error message
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL+"/pkg.Svc/Method", "--grpc", "--http", "1", "--format", "on")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "INTERNAL")
		assertBufContains(t, res.stderr, "oh no!")
	})

	t.Run("grpc client streaming", func(t *testing.T) {
		t.Parallel()
		// Build a FileDescriptorSet with a client-streaming method.
		boolTrue := true
		strType := descriptorpb.FieldDescriptorProto_TYPE_STRING
		int64Type := descriptorpb.FieldDescriptorProto_TYPE_INT64
		fds := &descriptorpb.FileDescriptorSet{
			File: []*descriptorpb.FileDescriptorProto{
				{
					Name:    new("stream.proto"),
					Package: new("streampkg"),
					Syntax:  new("proto3"),
					MessageType: []*descriptorpb.DescriptorProto{
						{
							Name: new("StreamRequest"),
							Field: []*descriptorpb.FieldDescriptorProto{
								{
									Name:   new("value"),
									Number: new(int32(1)),
									Type:   &strType,
								},
							},
						},
						{
							Name: new("StreamResponse"),
							Field: []*descriptorpb.FieldDescriptorProto{
								{
									Name:   new("count"),
									Number: new(int32(1)),
									Type:   &int64Type,
								},
							},
						},
					},
					Service: []*descriptorpb.ServiceDescriptorProto{
						{
							Name: new("StreamService"),
							Method: []*descriptorpb.MethodDescriptorProto{
								{
									Name:            new("ClientStream"),
									InputType:       new(".streampkg.StreamRequest"),
									OutputType:      new(".streampkg.StreamResponse"),
									ClientStreaming: &boolTrue,
								},
							},
						},
					},
				},
			},
		}

		// Serialize the descriptor set to a temp file.
		descData, err := protoMarshal.Marshal(fds)
		if err != nil {
			t.Fatalf("failed to marshal descriptor set: %v", err)
		}
		descFile := filepath.Join(t.TempDir(), "stream.pb")
		if err := os.WriteFile(descFile, descData, 0644); err != nil {
			t.Fatalf("failed to write descriptor file: %v", err)
		}

		// Server reads gRPC frames from request body, counts them,
		// and returns count as a gRPC-framed protobuf response.
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			// Count incoming gRPC frames.
			var count int
			for {
				var header [5]byte
				_, err := io.ReadFull(r.Body, header[:])
				if err != nil {
					break
				}
				length := binary.BigEndian.Uint32(header[1:5])
				if length > 0 {
					buf := make([]byte, length)
					_, err = io.ReadFull(r.Body, buf)
					if err != nil {
						break
					}
				}
				count++
			}

			// Build response: field 1 (count) as varint.
			var respData []byte
			respData = protowire.AppendTag(respData, 1, protowire.VarintType)
			respData = protowire.AppendVarint(respData, uint64(count))

			// Frame the response.
			framedResp := make([]byte, 5+len(respData))
			framedResp[0] = 0
			binary.BigEndian.PutUint32(framedResp[1:5], uint32(len(respData)))
			copy(framedResp[5:], respData)

			w.Header().Set("Content-Type", "application/grpc+proto")
			w.WriteHeader(200)
			w.Write(framedResp)
		})
		t.Cleanup(func() { server.Close() })

		t.Run("multiple messages", func(t *testing.T) {
			t.Parallel()
			data := `{"value":"one"}{"value":"two"}{"value":"three"}`
			res := runFetch(t, fetchPath,
				server.URL+"/streampkg.StreamService/ClientStream",
				"--grpc", "--proto-desc", descFile,
				"-d", data,
				"--http", "1", "--format", "on")
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stdout, "3")
		})

		t.Run("single message", func(t *testing.T) {
			t.Parallel()
			data := `{"value":"only"}`
			res := runFetch(t, fetchPath,
				server.URL+"/streampkg.StreamService/ClientStream",
				"--grpc", "--proto-desc", descFile,
				"-d", data,
				"--http", "1", "--format", "on")
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stdout, "1")
		})

		t.Run("empty stream", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath,
				server.URL+"/streampkg.StreamService/ClientStream",
				"--grpc", "--proto-desc", descFile,
				"--http", "1", "--format", "on")
			assertExitCode(t, 0, res)
		})

		t.Run("proto-file compiles local schema", func(t *testing.T) {
			t.Parallel()
			if _, err := exec.LookPath("protoc"); err != nil {
				t.Skip("protoc not found in PATH, skipping proto-file integration test")
			}
			protoFile := filepath.Join(t.TempDir(), "stream.proto")
			if err := os.WriteFile(protoFile, []byte(`
syntax = "proto3";
package streampkg;

message StreamRequest {
  string value = 1;
}

message StreamResponse {
  int64 count = 1;
}

service StreamService {
  rpc ClientStream(stream StreamRequest) returns (StreamResponse);
}
`), 0644); err != nil {
				t.Fatalf("failed to write proto file: %v", err)
			}

			res := runFetch(t, fetchPath, "--grpc-list", "--proto-file", protoFile)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stdout, "streampkg.StreamService")

			res = runFetch(t, fetchPath,
				server.URL+"/streampkg.StreamService/ClientStream",
				"--grpc", "--proto-file", protoFile,
				"-d", `{"value":"one"}{"value":"two"}`,
				"--http", "1", "--format", "on")
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stdout, "2")
		})
	})

	t.Run("proto flags mutual exclusivity", func(t *testing.T) {
		t.Parallel()
		// proto-file and proto-desc cannot be used together
		// Create temp files so we get past file existence validation
		tmpDir := t.TempDir()
		protoFile := filepath.Join(tmpDir, "a.proto")
		descFile := filepath.Join(tmpDir, "b.pb")
		os.WriteFile(protoFile, []byte("syntax = \"proto3\";"), 0644)
		os.WriteFile(descFile, []byte{}, 0644)

		res := runFetch(t, fetchPath, "http://example.com/svc/Method", "--grpc", "--proto-file", protoFile, "--proto-desc", descFile)
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "cannot be used together")
	})

	t.Run("proto-file requires protoc", func(t *testing.T) {
		t.Parallel()
		// If protoc isn't found, we should get a helpful error.
		// This test will only fail if protoc is not installed.
		// When protoc IS installed, it should fail because the file doesn't exist.
		res := runFetch(t, fetchPath, "http://example.com/svc/Method", "--grpc", "--proto-file", "/nonexistent/file.proto")
		assertExitCode(t, 1, res)
		// Should either complain about protoc not found or file not found
		if !strings.Contains(res.stderr.String(), "protoc") && !strings.Contains(res.stderr.String(), "exist") {
			t.Fatalf("expected error about protoc or file not found, got: %s", res.stderr.String())
		}
	})

	t.Run("proto-desc file not found", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "http://example.com/svc/Method", "--grpc", "--proto-desc", "/nonexistent/file.pb")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "does not exist")
	})

	t.Run("grpc reflection discovery and calls", func(t *testing.T) {
		t.Parallel()

		t.Run("tls reflection supports list describe and json call", func(t *testing.T) {
			t.Parallel()
			server := startReflectionGRPCServer(t, true, true)
			t.Cleanup(server.cleanup)

			res := runFetch(t, fetchPath, "--grpc-list", "--ca-cert", server.caCertPath, server.url)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stdout, "grpc.health.v1.Health")

			res = runFetch(t, fetchPath, "--grpc-describe", "grpc.health.v1.Health/Check", "--ca-cert", server.caCertPath, server.url)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stdout, "method grpc.health.v1.Health/Check")
			assertBufContains(t, res.stdout, "rpc: unary")
			assertBufContains(t, res.stdout, "request: grpc.health.v1.HealthCheckRequest")

			res = runFetch(t, fetchPath,
				server.url+"/grpc.health.v1.Health/Check",
				"--grpc", "--ca-cert", server.caCertPath,
				"-j", `{"service":""}`,
				"--format", "on",
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stdout, `"status": "SERVING"`)
		})

		t.Run("plaintext h2c reflection works for local servers", func(t *testing.T) {
			t.Parallel()
			server := startReflectionGRPCServer(t, false, true)
			t.Cleanup(server.cleanup)

			res := runFetch(t, fetchPath, "--grpc-list", server.url)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stdout, "grpc.health.v1.Health")

			res = runFetch(t, fetchPath,
				server.url+"/grpc.health.v1.Health/Check",
				"--grpc",
				"-j", `{"service":""}`,
				"--format", "on",
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stdout, `"status": "SERVING"`)
		})

		t.Run("reflection unavailable errors are actionable", func(t *testing.T) {
			t.Parallel()
			server := startReflectionGRPCServer(t, false, false)
			t.Cleanup(server.cleanup)

			res := runFetch(t, fetchPath, "--grpc-list", server.url)
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "gRPC reflection is unavailable")
			assertBufContains(t, res.stderr, "--proto-file")

			res = runFetch(t, fetchPath,
				server.url+"/grpc.health.v1.Health/Check",
				"--grpc",
				"-j", `{"service":""}`,
			)
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "gRPC reflection is unavailable")
			assertBufContains(t, res.stderr, "--proto-desc")

			res = runFetch(t, fetchPath,
				server.url+"/grpc.health.v1.Health/Check",
				"--grpc", "--format", "on",
			)
			assertExitCode(t, 0, res)
			assertBufNotEmpty(t, res.stdout)
		})

		t.Run("local schema discovery runs offline and wins over reflection", func(t *testing.T) {
			t.Parallel()
			descFile := writeHealthDescriptorSet(t)

			res := runFetch(t, fetchPath, "--grpc-list", "--proto-desc", descFile)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stdout, "grpc.health.v1.Health")

			res = runFetch(t, fetchPath,
				"--grpc-describe", "grpc.health.v1.Health",
				"--proto-desc", descFile,
				"http://127.0.0.1:1",
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stdout, "service grpc.health.v1.Health")
		})
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()
		// Copy the binary to a test-specific directory so the update
		// test doesn't modify the shared fetchPath.
		updateDir := t.TempDir()
		updateFetchPath := filepath.Join(updateDir, getExeName())
		copyFile(t, fetchPath, updateFetchPath)

		var empty string
		var urlStr atomic.Pointer[string]
		urlStr.Store(&empty)
		var newVersion atomic.Pointer[string]
		newVersion.Store(&version)
		var updateRequests atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			updateRequests.Add(1)
			if r.URL.Path != "/artifact" {
				type Asset struct {
					Name string `json:"name"`
					URL  string `json:"browser_download_url"`
				}
				type Release struct {
					TagName string  `json:"tag_name"`
					Assets  []Asset `json:"assets"`
				}

				w.WriteHeader(200)
				rel := Release{TagName: *newVersion.Load()}
				suffix := "tar.gz"
				if runtime.GOOS == "windows" {
					suffix = "zip"
				}
				rel.Assets = append(rel.Assets, Asset{
					Name: fmt.Sprintf("fetch-%s-%s-%s.%s",
						*newVersion.Load(), runtime.GOOS, runtime.GOARCH, suffix),
					URL: *urlStr.Load() + "/artifact",
				})
				json.NewEncoder(w).Encode(rel)
				return
			}

			f, err := os.Open(updateFetchPath)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			defer f.Close()
			stat, err := f.Stat()
			if err != nil {
				w.WriteHeader(400)
				return
			}

			buf := new(bytes.Buffer)
			if runtime.GOOS == "windows" {
				zw := zip.NewWriter(buf)
				h, err := zip.FileInfoHeader(stat)
				if err != nil {
					w.WriteHeader(400)
					return
				}
				hw, err := zw.CreateHeader(h)
				if err != nil {
					w.WriteHeader(400)
					return
				}
				if _, err = io.Copy(hw, f); err != nil {
					w.WriteHeader(400)
					return
				}
				zw.Close()
			} else {
				gw := gzip.NewWriter(buf)
				tw := tar.NewWriter(gw)
				h, err := tar.FileInfoHeader(stat, "")
				if err != nil {
					w.WriteHeader(400)
					return
				}
				err = tw.WriteHeader(h)
				if err != nil {
					w.WriteHeader(400)
					return
				}
				if _, err = io.Copy(tw, f); err != nil {
					w.WriteHeader(400)
					return
				}
				tw.Close()
				gw.Close()
			}

			w.WriteHeader(200)
			w.Write(buf.Bytes())
		})
		defer server.Close()
		urlStr.Store(&server.URL)

		updateEnv := []string{"FETCH_INTERNAL_UPDATE_URL=" + server.URL}

		origModTime := getModTime(t, updateFetchPath)

		// Test update using latest version.
		res := runFetchOpts(t, updateFetchPath, fetchOpts{env: updateEnv}, server.URL, "--update")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "Already using the latest version")
		if s := listFiles(t, filepath.Dir(updateFetchPath)); len(s) > 1 {
			t.Fatalf("unexpected files after updating: %v", s)
		}
		if !getModTime(t, updateFetchPath).Equal(origModTime) {
			t.Fatal("mod times after non-update are not equal")
		}

		// Test full update.
		newStr := "v(new)"
		newVersion.Store(&newStr)
		res = runFetchOpts(t, updateFetchPath, fetchOpts{env: updateEnv}, server.URL, "--update")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "Updated fetch:")
		assertBufContains(t, res.stderr, "Changelog:")
		if s := listFiles(t, filepath.Dir(updateFetchPath)); len(s) > 1 {
			t.Fatalf("unexpected files after updating: %v", s)
		}
		// Verify that the mod time has changed on the file.
		afterModTime := getModTime(t, updateFetchPath)
		if origModTime.Equal(afterModTime) {
			t.Fatal("mod times are equal")
		}

		// Ensure the new fetch binary still works.
		res = runFetchOpts(t, updateFetchPath, fetchOpts{env: updateEnv}, "--version")
		assertExitCode(t, 0, res)

		// Test dry-run update when already on latest version.
		newVersion.Store(&version)
		dryRunModTime := getModTime(t, updateFetchPath)
		res = runFetchOpts(t, updateFetchPath, fetchOpts{env: updateEnv}, server.URL, "--update", "--dry-run")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "Already using the latest version")
		if !getModTime(t, updateFetchPath).Equal(dryRunModTime) {
			t.Fatal("binary was modified during dry-run update (same version)")
		}

		// Test dry-run update when a new version is available.
		newVersion.Store(&newStr)
		dryRunModTime = getModTime(t, updateFetchPath)
		res = runFetchOpts(t, updateFetchPath, fetchOpts{env: updateEnv}, server.URL, "--update", "--dry-run")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "Update available")
		assertBufContains(t, res.stderr, newStr)
		assertBufNotContains(t, res.stderr, "Updated fetch:")
		assertBufNotContains(t, res.stderr, "Downloading")
		if !getModTime(t, updateFetchPath).Equal(dryRunModTime) {
			t.Fatal("binary was modified during dry-run update")
		}

		// Metadata-only commands should not start background auto-updates.
		metadataRequests := updateRequests.Load()
		metadataModTime := getModTime(t, updateFetchPath)
		res = runFetchOpts(t, updateFetchPath, fetchOpts{env: updateEnv}, "--version", "--auto-update", "0s")
		assertExitCode(t, 0, res)
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if updateRequests.Load() != metadataRequests {
				t.Fatal("metadata command started an auto-update request")
			}
			time.Sleep(25 * time.Millisecond)
		}
		if !getModTime(t, updateFetchPath).Equal(metadataModTime) {
			t.Fatal("metadata command modified the binary")
		}

		// Test the auto-update functionality.
		res = runFetchOpts(t, updateFetchPath, fetchOpts{env: updateEnv}, server.URL, "--auto-update", "0s")
		assertExitCode(t, 0, res)
		var n int
		for {
			mt := getOptionalModTime(t, updateFetchPath)
			if mt != nil && !mt.Equal(afterModTime) {
				break
			}
			if n > 100 {
				t.Fatal("timed out waiting for self-update to complete")
			}
			time.Sleep(100 * time.Millisecond)
			n++
		}

		// Ensure the new fetch binary still works.
		res = runFetchOpts(t, updateFetchPath, fetchOpts{env: updateEnv}, "--version")
		assertExitCode(t, 0, res)
	})

	t.Run("mtls", func(t *testing.T) {
		t.Parallel()
		mtlsDir := t.TempDir()

		// Generate test CA, server cert, and client cert.
		caCert, caKey := generateCACert(t)
		serverCert, serverKey := generateCert(t, caCert, caKey, "server")
		clientCert, clientKey := generateCert(t, caCert, caKey, "client")

		// Write certs to temp files.
		caCertPath := writeTempPEM(t, mtlsDir, "ca.crt", "CERTIFICATE", caCert.Raw)
		serverCertPath := writeTempPEM(t, mtlsDir, "server.crt", "CERTIFICATE", serverCert.Raw)
		serverKeyPath := writeTempPEM(t, mtlsDir, "server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))
		clientCertPath := writeTempPEM(t, mtlsDir, "client.crt", "CERTIFICATE", clientCert.Raw)
		clientKeyPath := writeTempPEM(t, mtlsDir, "client.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))

		// Create combined cert+key file.
		combinedPath := filepath.Join(mtlsDir, "client-combined.pem")
		combinedData := append(
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw}),
			pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})...,
		)
		if err := os.WriteFile(combinedPath, combinedData, 0600); err != nil {
			t.Fatalf("unable to write combined pem: %s", err.Error())
		}

		// Create mTLS server.
		server := startMTLSServer(t, serverCertPath, serverKeyPath, caCertPath)
		t.Cleanup(func() { server.Close() })

		t.Run("successful mtls with separate cert and key", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--ca-cert", caCertPath,
				"--cert", clientCertPath,
				"--key", clientKeyPath,
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "200 OK")
			assertBufEquals(t, res.stdout, "mtls-success")
		})

		t.Run("successful mtls with combined cert+key file", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--ca-cert", caCertPath,
				"--cert", combinedPath,
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "200 OK")
			assertBufEquals(t, res.stdout, "mtls-success")
		})

		t.Run("missing client cert fails", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 1, res)
			// Server requires client cert, so connection should fail.
			assertBufContains(t, res.stderr, "error")
		})

		t.Run("cert without key fails", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--ca-cert", caCertPath,
				"--cert", clientCertPath,
			)
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "may require a private key")
		})

		t.Run("key without cert fails", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--ca-cert", caCertPath,
				"--key", clientKeyPath,
			)
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "'--key' requires '--cert'")
		})

		t.Run("cert file not found", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--cert", "/nonexistent/client.crt",
				"--key", clientKeyPath,
			)
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "does not exist")
		})

		t.Run("key file not found", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--cert", clientCertPath,
				"--key", "/nonexistent/client.key",
			)
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "does not exist")
		})
	})

	t.Run("tls version bounds", func(t *testing.T) {
		t.Parallel()
		tlsDir := t.TempDir()

		caCert, caKey := generateCACert(t)
		serverCert, serverKey := generateCert(t, caCert, caKey, "tls-version-server")
		caCertPath := writeTempPEM(t, tlsDir, "version-ca.crt", "CERTIFICATE", caCert.Raw)
		serverCertPath := writeTempPEM(t, tlsDir, "version-server.crt", "CERTIFICATE", serverCert.Raw)
		serverKeyPath := writeTempPEM(t, tlsDir, "version-server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))

		tlsCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
		if err != nil {
			t.Fatalf("unable to load server cert: %s", err.Error())
		}
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "tls-version-ok")
		}))
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		}
		server.StartTLS()
		t.Cleanup(func() { server.Close() })

		res := runFetch(t, fetchPath, server.URL,
			"--ca-cert", caCertPath,
			"--min-tls", "1.3",
			"--max-tls", "1.3",
		)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "tls-version-ok")

		res = runFetch(t, fetchPath, server.URL,
			"--ca-cert", caCertPath,
			"--max-tls", "1.2",
		)
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "tls")

		res = runFetch(t, fetchPath, server.URL,
			"--inspect-tls",
			"--ca-cert", caCertPath,
			"--min-tls", "1.3",
			"--max-tls", "1.3",
		)
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "TLS 1.3")

		res = runFetch(t, fetchPath, server.URL,
			"--inspect-tls",
			"--ca-cert", caCertPath,
			"--max-tls", "1.2",
		)
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "tls")
	})

	t.Run("inspect-tls", func(t *testing.T) {
		t.Parallel()
		tlsDir := t.TempDir()

		// Generate test CA and server cert with SANs.
		caCert, caKey := generateCACert(t)
		serverCert, serverKey := generateCert(t, caCert, caKey, "test-server")
		caCertPath := writeTempPEM(t, tlsDir, "inspect-ca.crt", "CERTIFICATE", caCert.Raw)
		serverCertPath := writeTempPEM(t, tlsDir, "inspect-server.crt", "CERTIFICATE", serverCert.Raw)
		serverKeyPath := writeTempPEM(t, tlsDir, "inspect-server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))

		// Start a TLS server.
		tlsCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
		if err != nil {
			t.Fatalf("unable to load server cert: %s", err.Error())
		}
		tlsCert.OCSPStaple = createOCSPResponse(t, caCert, serverCert, caKey, ocsp.Good)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "tls-body")
		}))
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			NextProtos:   []string{"h2", "http/1.1"},
		}
		server.StartTLS()
		t.Cleanup(func() { server.Close() })

		t.Run("shows certificate chain", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "Certificate chain")
			assertBufContains(t, res.stderr, "test-server")
			assertBufContains(t, res.stderr, "Test CA")
			// Body should NOT be printed.
			assertBufEmpty(t, res.stdout)
		})

		t.Run("shows TLS version", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "TLS 1.3")
		})

		t.Run("shows default ALPN negotiation", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "ALPN: h2")
		})

		t.Run("honors HTTP/1 ALPN setting", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--http", "1",
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "ALPN: http/1.1")
		})

		t.Run("shows SANs", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "SANs:")
			assertBufContains(t, res.stderr, "localhost")
		})

		t.Run("shows expiry info", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 0, res)
			// The test cert expires in 1 hour, so < 1 day.
			assertBufContains(t, res.stderr, "expires in <1 day")
		})

		t.Run("shows stapled OCSP status", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "OCSP: good (stapled)")
		})

		t.Run("colors inspection output", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--ca-cert", caCertPath,
				"--color", "on",
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "\x1b[1m\x1b[33mTLS 1.3\x1b[0m")
			assertBufContains(t, res.stderr, "ALPN: \x1b[3mh2\x1b[0m")
			assertBufContains(t, res.stderr, "\x1b[1mCertificate chain\x1b[0m")
			assertBufContains(t, res.stderr, "\x1b[31mexpires in <1 day\x1b[0m")
			assertBufContains(t, res.stderr, "\x1b[32mgood\x1b[0m (stapled)")
			assertBufEmpty(t, res.stdout)
		})

		t.Run("works with insecure flag", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--insecure",
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "Certificate chain")
			assertBufContains(t, res.stderr, "test-server")
		})

		t.Run("rejects http url", func(t *testing.T) {
			t.Parallel()
			httpServer := startServer(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "ok")
			})
			defer httpServer.Close()

			res := runFetch(t, fetchPath, httpServer.URL, "--inspect-tls")
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "--inspect-tls requires an HTTPS URL")
		})

		t.Run("works with verbose flag", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--ca-cert", caCertPath,
				"-v",
			)
			assertExitCode(t, 0, res)
			// No HTTP request is made, so no response metadata.
			assertBufContains(t, res.stderr, "Certificate chain")
			assertBufEmpty(t, res.stdout)
		})

		t.Run("warns when timing flag is used", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--timing",
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "--inspect-tls ignores: --timing")
			assertBufContains(t, res.stderr, "Certificate chain")
		})

		t.Run("warns on incompatible flags", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--ca-cert", caCertPath,
				"-d", "hello",
				"--timing",
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "--inspect-tls ignores:")
			assertBufContains(t, res.stderr, "--data/--json/--xml")
			assertBufContains(t, res.stderr, "--timing")
			assertBufContains(t, res.stderr, "Certificate chain")
			assertBufEmpty(t, res.stdout)
		})
	})

	t.Run("inspect-tls http3", func(t *testing.T) {
		t.Parallel()
		tlsDir := t.TempDir()

		caCert, caKey := generateCACert(t)
		serverCert, serverKey := generateCert(t, caCert, caKey, "quic-server")
		caCertPath := writeTempPEM(t, tlsDir, "quic-ca.crt", "CERTIFICATE", caCert.Raw)
		handshakeSeen := make(chan struct{}, 1)

		ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{serverCert.Raw},
				PrivateKey:  serverKey,
				Leaf:        serverCert,
			}},
			NextProtos: []string{http3.NextProtoH3},
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				select {
				case handshakeSeen <- struct{}{}:
				default:
				}
				return nil, nil
			},
		}, nil)
		if err != nil {
			t.Fatalf("unable to start QUIC listener: %s", err.Error())
		}
		t.Cleanup(func() { ln.Close() })

		res := runFetch(t, fetchPath, "https://"+ln.Addr().String(),
			"--inspect-tls",
			"--http", "3",
			"--ca-cert", caCertPath,
		)
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "TLS 1.3")
		assertBufContains(t, res.stderr, "ALPN: h3")
		assertBufContains(t, res.stderr, "quic-server")

		select {
		case <-handshakeSeen:
		case <-time.After(5 * time.Second):
			t.Fatal("server did not observe QUIC TLS handshake")
		}
	})

	t.Run("session", func(t *testing.T) {
		t.Parallel()
		t.Run("cookies persist across requests", func(t *testing.T) {
			t.Parallel()
			sessDir := t.TempDir()
			sessEnv := []string{"FETCH_INTERNAL_SESSIONS_DIR=" + sessDir}

			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" {
					http.SetCookie(w, &http.Cookie{
						Name:  "session_id",
						Value: "abc123",
						Path:  "/",
					})
					io.WriteString(w, "logged in")
					return
				}
				if r.URL.Path == "/dashboard" {
					cookie, err := r.Cookie("session_id")
					if err != nil || cookie.Value != "abc123" {
						w.WriteHeader(401)
						io.WriteString(w, "unauthorized")
						return
					}
					io.WriteString(w, "welcome")
					return
				}
			})
			defer server.Close()

			// First request: server sets cookie.
			res := runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv}, server.URL+"/login", "--session", "integ-test")
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "logged in")

			// Second request: cookie is sent automatically.
			res = runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv}, server.URL+"/dashboard", "--session", "integ-test")
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "welcome")

			// Without session: cookie is NOT sent.
			res = runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv}, server.URL+"/dashboard")
			assertExitCode(t, 4, res)
			assertBufEquals(t, res.stdout, "unauthorized")
		})

		t.Run("expired cookies are not sent", func(t *testing.T) {
			t.Parallel()
			sessDir := t.TempDir()
			sessEnv := []string{"FETCH_INTERNAL_SESSIONS_DIR=" + sessDir}

			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/set" {
					http.SetCookie(w, &http.Cookie{
						Name:    "expired",
						Value:   "old",
						Path:    "/",
						Expires: time.Now().Add(-time.Hour),
					})
					http.SetCookie(w, &http.Cookie{
						Name:    "valid",
						Value:   "yes",
						Path:    "/",
						Expires: time.Now().Add(time.Hour),
					})
					return
				}
				if r.URL.Path == "/check" {
					_, err := r.Cookie("expired")
					if err == nil {
						w.WriteHeader(400)
						io.WriteString(w, "expired cookie was sent")
						return
					}
					cookie, err := r.Cookie("valid")
					if err != nil || cookie.Value != "yes" {
						w.WriteHeader(400)
						io.WriteString(w, "valid cookie missing")
						return
					}
					io.WriteString(w, "ok")
					return
				}
			})
			defer server.Close()

			res := runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv}, server.URL+"/set", "--session", "expiry-integ")
			assertExitCode(t, 0, res)

			res = runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv}, server.URL+"/check", "--session", "expiry-integ")
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "ok")
		})

		t.Run("different session names are isolated", func(t *testing.T) {
			t.Parallel()
			sessDir := t.TempDir()
			sessEnv := []string{"FETCH_INTERNAL_SESSIONS_DIR=" + sessDir}

			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/set" {
					http.SetCookie(w, &http.Cookie{
						Name:  "token",
						Value: r.URL.Query().Get("v"),
						Path:  "/",
					})
					return
				}
				if r.URL.Path == "/get" {
					cookie, err := r.Cookie("token")
					if err != nil {
						io.WriteString(w, "none")
						return
					}
					io.WriteString(w, cookie.Value)
					return
				}
			})
			defer server.Close()

			// Set different cookies in different sessions.
			res := runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv}, server.URL+"/set?v=alpha", "--session", "sess-a")
			assertExitCode(t, 0, res)

			res = runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv}, server.URL+"/set?v=beta", "--session", "sess-b")
			assertExitCode(t, 0, res)

			// Verify sessions are isolated.
			res = runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv}, server.URL+"/get", "--session", "sess-a")
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "alpha")

			res = runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv}, server.URL+"/get", "--session", "sess-b")
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "beta")
		})

		t.Run("public suffix domain cookies are rejected", func(t *testing.T) {
			t.Parallel()
			sessDir := t.TempDir()
			sessEnv := []string{
				"FETCH_INTERNAL_SESSIONS_DIR=" + sessDir,
				"HTTP_PROXY=",
				"HTTPS_PROXY=",
				"ALL_PROXY=",
				"NO_PROXY=*",
			}

			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/set" {
					http.SetCookie(w, &http.Cookie{
						Name:   "token",
						Value:  "secret",
						Domain: "github.io",
						Path:   "/",
					})
					io.WriteString(w, "set")
					return
				}
				if r.URL.Path == "/check" {
					if _, err := r.Cookie("token"); err == nil {
						w.WriteHeader(500)
						io.WriteString(w, "public suffix cookie was sent")
						return
					}
					io.WriteString(w, "clean")
					return
				}
			})
			defer server.Close()

			_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatalf("unable to split host and port from server url: %s", err.Error())
			}
			dnsAddr := startUDPDNSServer(t, "user.github.io.", net.ParseIP("127.0.0.1"))
			baseURL := "http://user.github.io:" + port

			res := runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv}, "--dns-server", dnsAddr, baseURL+"/set", "--session", "psl-integ")
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "set")

			res = runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv}, "--dns-server", dnsAddr, baseURL+"/check", "--session", "psl-integ")
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "clean")
		})

		t.Run("invalid session name rejected", func(t *testing.T) {
			t.Parallel()
			sessEnv := []string{"FETCH_INTERNAL_SESSIONS_DIR=" + t.TempDir()}
			res := runFetchOpts(t, fetchPath, fetchOpts{env: sessEnv}, "http://example.com", "--session", "../evil")
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "session")
		})
	})

	t.Run("copy", func(t *testing.T) {
		t.Parallel()
		t.Run("stdout still has body", func(t *testing.T) {
			t.Parallel()
			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				io.WriteString(w, `{"hello":"world"}`)
			})
			defer server.Close()

			res := runFetch(t, fetchPath, "--copy", "--no-pager", "--format=off", server.URL)
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, `{"hello":"world"}`)
		})

		t.Run("works with output flag", func(t *testing.T) {
			t.Parallel()
			const data = "file and clipboard data"
			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				io.WriteString(w, data)
			})
			defer server.Close()

			dir, err := os.MkdirTemp("", "")
			if err != nil {
				t.Fatalf("unable to create temp dir: %s", err.Error())
			}
			defer os.RemoveAll(dir)

			path := filepath.Join(dir, "output")
			res := runFetch(t, fetchPath, "--copy", "-o", path, server.URL)
			assertExitCode(t, 0, res)

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("unable to read output file: %s", err.Error())
			}
			if string(raw) != data {
				t.Fatalf("unexpected data in output file: %q", raw)
			}
		})

		t.Run("head request with copy", func(t *testing.T) {
			t.Parallel()
			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
			})
			defer server.Close()

			res := runFetch(t, fetchPath, "--copy", "-m", "HEAD", server.URL)
			assertExitCode(t, 0, res)
			assertBufEmpty(t, res.stdout)
		})

		t.Run("copy with silent mode", func(t *testing.T) {
			t.Parallel()
			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(200)
				io.WriteString(w, "silent copy")
			})
			defer server.Close()

			res := runFetch(t, fetchPath, "--copy", "-s", "--no-pager", server.URL)
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "silent copy")
			// In silent mode, stderr should not contain response metadata.
			assertBufNotContains(t, res.stderr, "200 OK")
		})

		t.Run("copy with SSE response", func(t *testing.T) {
			t.Parallel()
			const data = "data:{\"key\":\"val\"}\n\nevent:ev1\ndata: hello\n\n"
			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(200)
				io.WriteString(w, data)
			})
			defer server.Close()

			res := runFetch(t, fetchPath, "--copy", "--no-pager", "--format", "off", server.URL)
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, data)
			assertBufNotContains(t, res.stderr, "not supported")
		})

		t.Run("copy with NDJSON response", func(t *testing.T) {
			t.Parallel()
			const data = "{\"a\":1}\n{\"b\":2}\n"
			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/x-ndjson")
				w.WriteHeader(200)
				io.WriteString(w, data)
			})
			defer server.Close()

			res := runFetch(t, fetchPath, "--copy", "--no-pager", "--format", "off", server.URL)
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, data)
			assertBufNotContains(t, res.stderr, "not supported")
		})
	})

	t.Run("discard", func(t *testing.T) {
		t.Parallel()
		t.Run("basic", func(t *testing.T) {
			t.Parallel()
			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				io.WriteString(w, "hello world")
			})
			defer server.Close()

			res := runFetch(t, fetchPath, "--discard", server.URL)
			assertExitCode(t, 0, res)
			assertBufEmpty(t, res.stdout)
		})

		t.Run("with verbose", func(t *testing.T) {
			t.Parallel()
			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Test", "value")
				w.WriteHeader(200)
				io.WriteString(w, "body content")
			})
			defer server.Close()

			res := runFetch(t, fetchPath, "--discard", "-v", server.URL)
			assertExitCode(t, 0, res)
			assertBufEmpty(t, res.stdout)
			assertBufContains(t, res.stderr, "x-test")
		})

		t.Run("with timing", func(t *testing.T) {
			t.Parallel()
			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				io.WriteString(w, "body content")
			})
			defer server.Close()

			res := runFetch(t, fetchPath, "--discard", "--timing", server.URL)
			assertExitCode(t, 0, res)
			assertBufEmpty(t, res.stdout)
			assertBufContains(t, res.stderr, "TTFB")
		})

		t.Run("error status", func(t *testing.T) {
			t.Parallel()
			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
				io.WriteString(w, "not found")
			})
			defer server.Close()

			res := runFetch(t, fetchPath, "--discard", server.URL)
			assertExitCode(t, 4, res)
			assertBufEmpty(t, res.stdout)
		})

		t.Run("exclusive with output", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, "--discard", "-o", "file.txt", "http://example.com")
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "cannot be used together")
		})

		t.Run("exclusive with copy", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, "--discard", "--copy", "http://example.com")
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "cannot be used together")
		})

		t.Run("exclusive with remote-name", func(t *testing.T) {
			t.Parallel()
			res := runFetch(t, fetchPath, "--discard", "-O", "http://example.com")
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "cannot be used together")
		})
	})

	t.Run("retry on 503", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			n := count.Add(1)
			if n <= 2 {
				w.WriteHeader(503)
				return
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "3", "--retry-delay", fastRetryDelay)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
		assertBufContains(t, res.stderr, "retry")
		if count.Load() != 3 {
			t.Fatalf("expected 3 requests, got %d", count.Load())
		}
	})

	t.Run("retry on 502", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			n := count.Add(1)
			if n <= 1 {
				w.WriteHeader(502)
				return
			}
			io.WriteString(w, "recovered")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "2", "--retry-delay", fastRetryDelay)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "recovered")
	})

	t.Run("retry on 504", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			n := count.Add(1)
			if n <= 1 {
				w.WriteHeader(504)
				return
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", fastRetryDelay)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("retry on 429", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			n := count.Add(1)
			if n <= 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(429)
				return
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", fastRetryDelay)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("no retry on 404", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			w.WriteHeader(404)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "3", "--retry-delay", fastRetryDelay)
		assertExitCode(t, 4, res)
		assertBufNotContains(t, res.stderr, "retry")
		if count.Load() != 1 {
			t.Fatalf("expected 1 request (no retries), got %d", count.Load())
		}
	})

	t.Run("no retry on 200", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "3", "--retry-delay", fastRetryDelay)
		assertExitCode(t, 0, res)
		if count.Load() != 1 {
			t.Fatalf("expected 1 request, got %d", count.Load())
		}
	})

	t.Run("retry exhausted", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			w.WriteHeader(503)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "2", "--retry-delay", fastRetryDelay)
		assertExitCode(t, 5, res)
		if count.Load() != 3 { // 1 initial + 2 retries
			t.Fatalf("expected 3 requests, got %d", count.Load())
		}
	})

	t.Run("retry with request body", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		var lastBody atomic.Pointer[string]
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			s := string(body)
			lastBody.Store(&s)
			n := count.Add(1)
			if n <= 1 {
				w.WriteHeader(503)
				return
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", fastRetryDelay,
			"-d", "test-body")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
		if *lastBody.Load() != "test-body" {
			t.Fatalf("body not replayed correctly: %s", *lastBody.Load())
		}
	})

	t.Run("retry silent", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			n := count.Add(1)
			if n <= 1 {
				w.WriteHeader(503)
				return
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", fastRetryDelay, "-s")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("retry verbose", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			n := count.Add(1)
			if n <= 1 {
				w.WriteHeader(503)
				return
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", fastRetryDelay, "-v")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "retry")
		assertBufNotContains(t, res.stderr, "* retry")
		assertBufContains(t, res.stderr, "200 OK")
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("retry verbose vv", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			n := count.Add(1)
			if n <= 1 {
				w.WriteHeader(503)
				return
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", fastRetryDelay, "-vv")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "* retry")
		assertBufContains(t, res.stderr, "> GET / HTTP/1.1")
		assertBufContains(t, res.stderr, "< HTTP/1.1 200 OK")
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("no retry on redirect limit exceeded", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			// Always redirect to self.
			http.Redirect(w, r, r.URL.Path, http.StatusFound)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "2", "--retry-delay", fastRetryDelay, "--redirects", "1")
		assertExitCode(t, 1, res)
		assertBufNotContains(t, res.stderr, "retry")
		assertBufContains(t, res.stderr, "exceeded maximum number of redirects")
	})

	t.Run("retry 0 no retry", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			w.WriteHeader(503)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "0", "--retry-delay", fastRetryDelay)
		assertExitCode(t, 5, res)
		if count.Load() != 1 {
			t.Fatalf("expected 1 request, got %d", count.Load())
		}
	})

	t.Run("sniff json without content-type", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			// Deliberately omit Content-Type header.
			w.Header().Del("Content-Type")
			w.WriteHeader(200)
			io.WriteString(w, `{"key":"value"}`)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "\"key\"")
		assertBufContains(t, res.stdout, "\"value\"")
	})

	t.Run("sniff xml without content-type", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Del("Content-Type")
			w.WriteHeader(200)
			io.WriteString(w, `<?xml version="1.0"?><root><item>hello</item></root>`)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "<root>")
		assertBufContains(t, res.stdout, "hello")
	})

	t.Run("sniff html without content-type", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Del("Content-Type")
			w.WriteHeader(200)
			io.WriteString(w, `<!doctype html><html><body>hello</body></html>`)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "hello")
	})

	t.Run("no sniff plain text without content-type", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Del("Content-Type")
			w.WriteHeader(200)
			io.WriteString(w, "just plain text")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--format", "on")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "just plain text")
	})

	t.Run("websocket echo with data flag", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			// Read one message, echo it, then close.
			typ, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			conn.Write(r.Context(), typ, data)
			conn.Close(websocket.StatusNormalClosure, "done")
		})
		defer server.Close()

		wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
		res := runFetch(t, fetchPath, wsURL, "-d", "hello", "--no-pager")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "hello")
	})

	t.Run("websocket scheme auto-detection", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			conn.Write(r.Context(), websocket.MessageText, []byte("pong"))
			conn.Close(websocket.StatusNormalClosure, "done")
		})
		defer server.Close()

		wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
		res := runFetch(t, fetchPath, wsURL, "--no-pager")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "pong")
	})

	t.Run("websocket verbose shows upgrade", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			conn.Write(r.Context(), websocket.MessageText, []byte("hi"))
			conn.Close(websocket.StatusNormalClosure, "done")
		})
		defer server.Close()

		wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
		res := runFetch(t, fetchPath, "-vv", wsURL, "--no-pager")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "101")
	})

	t.Run("websocket json formatting", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			conn.Write(r.Context(), websocket.MessageText, []byte(`{"key":"value"}`))
			conn.Close(websocket.StatusNormalClosure, "done")
		})
		defer server.Close()

		wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
		res := runFetch(t, fetchPath, wsURL, "--format", "on", "--color", "off", "--no-pager")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, `{ "key": "value" }`)
	})

	t.Run("websocket piped stdin", func(t *testing.T) {
		t.Parallel()
		var echoed atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			for {
				typ, data, err := conn.Read(r.Context())
				if err != nil {
					return
				}
				conn.Write(r.Context(), typ, data)
				if echoed.Add(1) == 2 {
					conn.Close(websocket.StatusNormalClosure, "done")
					return
				}
			}
		})
		defer server.Close()

		wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
		res := runFetchStdin(t, "line1\nline2\n", fetchPath, wsURL, "--no-pager")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "line1")
		assertBufContains(t, res.stdout, "line2")
	})

	t.Run("websocket auth header sent", func(t *testing.T) {
		t.Parallel()
		var gotAuth string
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			conn.Write(r.Context(), websocket.MessageText, []byte("authed"))
			conn.Close(websocket.StatusNormalClosure, "done")
		})
		defer server.Close()

		wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
		res := runFetch(t, fetchPath, wsURL, "--bearer", "mytoken", "--no-pager")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stdout, "authed")
		if gotAuth != "Bearer mytoken" {
			t.Fatalf("expected auth header 'Bearer mytoken', got %q", gotAuth)
		}
	})

	t.Run("websocket exclusive with grpc", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--grpc", "ws://localhost:1234")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "cannot be used together")
	})

	t.Run("websocket non-GET method warns", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			conn.Write(r.Context(), websocket.MessageText, []byte("ok"))
			conn.Close(websocket.StatusNormalClosure, "done")
		})
		defer server.Close()

		wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
		res := runFetch(t, fetchPath, "-X", "POST", wsURL, "--no-pager")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "ignoring method POST")
		assertBufContains(t, res.stdout, "ok")
	})

	t.Run("websocket dry-run", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--dry-run", "ws://localhost:1234/chat")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "GET")
		assertBufContains(t, res.stderr, "/chat")
	})

	t.Run("websocket dry-run non-GET shows effective GET", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--dry-run", "-X", "POST", "ws://localhost:1234/chat")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "ignoring method POST")
		assertBufContains(t, res.stderr, "GET /chat")
		assertBufNotContains(t, res.stderr, "POST /chat")
	})

	t.Run("websocket ctrl-c exits", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS == "windows" {
			t.Skip("signal test not supported on Windows")
		}

		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			conn.Write(r.Context(), websocket.MessageText, []byte("hello"))
			// Keep connection open until client disconnects.
			<-r.Context().Done()
		})
		defer server.Close()

		wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
		var stdout syncBuffer
		cmd := exec.Command(fetchPath, wsURL, "--no-pager")
		cmd.Stdout = &stdout
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatalf("failed to start: %v", err)
		}

		// Wait for the message to appear in stdout.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if strings.Contains(stdout.String(), "hello") {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !strings.Contains(stdout.String(), "hello") {
			t.Fatal("timed out waiting for WebSocket message")
		}

		// Send SIGINT and verify process exits promptly.
		cmd.Process.Signal(syscall.SIGINT)
		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()
		select {
		case <-done:
			// Process exited — success.
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			t.Fatal("process did not exit after SIGINT")
		}
	})

	t.Run("request ctrl-c reports signal", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS == "windows" {
			t.Skip("signal test not supported on Windows")
		}

		requestStarted := make(chan struct{})
		var once sync.Once
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			once.Do(func() {
				close(requestStarted)
			})
			<-r.Context().Done()
		})
		defer server.Close()

		var stdout syncBuffer
		var stderr syncBuffer
		cmd := exec.Command(fetchPath, server.URL, "--no-pager")
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("failed to start: %v", err)
		}

		select {
		case <-requestStarted:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			t.Fatal("timed out waiting for request")
		}

		if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
			cmd.Process.Kill()
			t.Fatalf("failed to signal process: %v", err)
		}

		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("process exited successfully after SIGINT, want exit code 1")
			}
			exitErr, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("unexpected wait error: %v", err)
			}
			if code := exitErr.ExitCode(); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			t.Fatal("process did not exit after SIGINT")
		}

		if got := stdout.String(); got != "" {
			t.Fatalf("stdout = %q, want empty", got)
		}
		if got := stderr.String(); !strings.Contains(got, "received signal: interrupt") {
			t.Fatalf("stderr = %q, want signal error", got)
		}
	})

	t.Run("retry on per-attempt timeout", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			n := count.Add(1)
			if n <= 1 {
				// First attempt: block until the client-side per-attempt
				// timeout cancels the request.
				<-r.Context().Done()
				return
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", fastRetryDelay, "--timeout", "0.1")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
		if count.Load() != 2 {
			t.Fatalf("expected 2 requests, got %d", count.Load())
		}
	})

	t.Run("timing waterfall", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "hello")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--timing")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "hello")
		// Don't assert specific phases (TCP, TTFB) — on fast local
		// connections they can be 0-duration and omitted.
		assertBufContains(t, res.stderr, "Total")
		assertBufContains(t, res.stderr, "█")
		assertBufContains(t, res.stderr, "─")
	})

	t.Run("timing waterfall short flag", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "hello")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "-T")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "hello")
		assertBufContains(t, res.stderr, "Total")
		assertBufContains(t, res.stderr, "█")
	})

	t.Run("timing waterfall without debug text", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "hello")
		})
		defer server.Close()

		// --timing alone should NOT produce -vvv inline debug text.
		res := runFetch(t, fetchPath, server.URL, "--timing")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "Total")
		assertBufNotContains(t, res.stderr, "* TCP:")
		assertBufNotContains(t, res.stderr, "* TTFB:")
	})

	t.Run("timing waterfall with debug", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "hello")
		})
		defer server.Close()

		// --timing -vvv should produce both inline debug text AND waterfall.
		res := runFetch(t, fetchPath, server.URL, "--timing", "-vvv")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "* TCP:")
		assertBufContains(t, res.stderr, "* TTFB:")
		assertBufContains(t, res.stderr, "Total")
		assertBufContains(t, res.stderr, "█")
	})

	t.Run("timing waterfall HEAD request", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--timing", "-m", "HEAD")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "Total")
		// No Body phase for HEAD requests.
		assertBufNotContains(t, res.stderr, "Body")
	})

	t.Run("timing waterfall with retry", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			n := count.Add(1)
			if n <= 1 {
				w.WriteHeader(503)
				return
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--timing", "--retry", "1", "--retry-delay", fastRetryDelay)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
		assertBufContains(t, res.stderr, "Total")
		assertBufContains(t, res.stderr, "█")
	})

	t.Run("timing waterfall websocket warning", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			conn.Write(r.Context(), websocket.MessageText, []byte("ok"))
			conn.Close(websocket.StatusNormalClosure, "done")
		})
		defer server.Close()

		wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
		res := runFetch(t, fetchPath, wsURL, "--timing", "--no-pager")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "--timing is not supported for WebSocket")
	})

	t.Run("from-curl basic GET", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			io.WriteString(w, "hello from curl")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, "--from-curl", "curl "+server.URL)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "hello from curl")
	})

	t.Run("from-curl without curl prefix", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			io.WriteString(w, "no prefix")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, "--from-curl", server.URL)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "no prefix")
	})

	t.Run("from-curl POST with data", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				w.WriteHeader(400)
				io.WriteString(w, "expected POST")
				return
			}
			body, _ := io.ReadAll(r.Body)
			w.WriteHeader(200)
			w.Write(body)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, "--from-curl", fmt.Sprintf(`curl -X POST -d "hello=world" %s`, server.URL))
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "hello=world")
	})

	t.Run("from-curl with headers", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			val := r.Header.Get("X-Custom")
			w.WriteHeader(200)
			io.WriteString(w, val)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, "--from-curl", fmt.Sprintf(`curl -H "X-Custom: test-value" %s`, server.URL))
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "test-value")
	})

	t.Run("from-curl with basic auth", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.WriteHeader(401)
				return
			}
			raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
			if err != nil {
				w.WriteHeader(400)
				return
			}
			w.WriteHeader(200)
			w.Write(raw)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, "--from-curl", fmt.Sprintf(`curl -u user:pass %s`, server.URL))
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "user:pass")
	})

	t.Run("from-curl key without cert is ignored", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "key-only-curl-ok")
		})
		defer server.Close()

		dir := t.TempDir()
		keyPath := writeTempPEM(t, dir, "curl-client.key", "RSA PRIVATE KEY", []byte("fake"))
		res := runFetch(t, fetchPath, "--from-curl", fmt.Sprintf(`curl --key %s %s`, keyPath, server.URL))
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "key-only-curl-ok")
	})

	t.Run("from-curl with verbose", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test-Header", "visible")
			w.WriteHeader(200)
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, "--from-curl", fmt.Sprintf(`curl -v %s`, server.URL))
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
		assertBufContains(t, res.stderr, "x-test-header")
	})

	t.Run("from-curl with retry", func(t *testing.T) {
		t.Parallel()
		var count atomic.Int32
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			if count.Add(1) < 2 {
				w.WriteHeader(503)
				return
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, "--from-curl", fmt.Sprintf(`curl --retry 2 --retry-delay %s %s`, fastRetryDelay, server.URL))
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("from-curl exclusive with URL", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--from-curl", "curl https://example.com", "https://other.com")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "cannot be used together")
	})

	t.Run("from-curl exclusive with method", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--from-curl", "curl https://example.com", "-m", "POST")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "cannot be used together")
	})

	t.Run("from-curl missing URL", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--from-curl", "curl -X POST")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "no URL provided")
	})

	t.Run("from-curl unknown flag", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--from-curl", "curl --unknown-flag https://example.com")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "unsupported curl flag")
	})

	t.Run("from-curl with dry-run", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--dry-run", "--from-curl", `curl -X PUT -H "Content-Type: application/json" -d '{"key":"value"}' https://example.com`)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "PUT")
		assertBufContains(t, res.stderr, "example.com")
	})

	t.Run("from-curl proto restricts to https", func(t *testing.T) {
		t.Parallel()
		res := runFetch(t, fetchPath, "--from-curl", `curl --proto '=https' http://example.com`)
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "not allowed by --proto")
	})

	t.Run("from-curl proto allows https", func(t *testing.T) {
		t.Parallel()
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, "--from-curl", fmt.Sprintf(`curl --proto '=http,https' %s`, server.URL))
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
	})
}

type runResult struct {
	state  *os.ProcessState
	stderr *bytes.Buffer
	stdout *bytes.Buffer
}

type fetchOpts struct {
	stdin string
	dir   string
	env   []string
}

func runFetch(t *testing.T, path string, args ...string) runResult {
	return runFetchOpts(t, path, fetchOpts{}, args...)
}

func runFetchStdin(t *testing.T, input, path string, args ...string) runResult {
	return runFetchOpts(t, path, fetchOpts{stdin: input}, args...)
}

func runFetchOpts(t *testing.T, path string, opts fetchOpts, args ...string) runResult {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	delay := 10 * time.Millisecond
	for {
		var stderr, stdout = new(bytes.Buffer), new(bytes.Buffer)
		cmd := exec.Command(path, args...)
		if opts.stdin != "" {
			cmd.Stdin = strings.NewReader(opts.stdin)
		}
		if opts.dir != "" {
			cmd.Dir = opts.dir
		}
		if len(opts.env) > 0 {
			cmd.Env = overlayEnv(os.Environ(), opts.env)
		}
		cmd.Stderr = stderr
		cmd.Stdout = stdout
		if err := cmd.Run(); err != nil {
			if isTextFileBusy(err) && time.Now().Before(deadline) {
				time.Sleep(delay)
				delay = min(delay*2, 100*time.Millisecond)
				continue
			}
			if _, ok := errors.AsType[*exec.ExitError](err); !ok {
				t.Fatalf("unexpected error running the fetch command: %s", err.Error())
			}
		}
		return runResult{
			state:  cmd.ProcessState,
			stderr: stderr,
			stdout: stdout,
		}
	}
}

func overlayEnv(base, overrides []string) []string {
	env := append([]string(nil), base...)
	index := make(map[string]int, len(env))
	for i, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			index[key] = i
		}
	}
	for _, entry := range overrides {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			env = append(env, entry)
			continue
		}
		if i, ok := index[key]; ok {
			env[i] = entry
			continue
		}
		index[key] = len(env)
		env = append(env, entry)
	}
	return env
}

func noProxyEnv(extra ...string) []string {
	env := []string{"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "NO_PROXY=*"}
	return append(env, extra...)
}

func isTextFileBusy(err error) bool {
	return strings.Contains(err.Error(), "text file busy")
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("unable to open source file: %s", err.Error())
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		t.Fatalf("unable to stat source file: %s", err.Error())
	}

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".fetch-copy-*")
	if err != nil {
		t.Fatalf("unable to create temporary destination file: %s", err.Error())
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(info.Mode()); err != nil {
		tmp.Close()
		t.Fatalf("unable to set destination file mode: %s", err.Error())
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		t.Fatalf("unable to copy file: %s", err.Error())
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		t.Fatalf("unable to sync destination file: %s", err.Error())
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("unable to close destination file: %s", err.Error())
	}

	if err := os.Rename(tmpPath, dst); err != nil {
		t.Fatalf("unable to move destination file into place: %s", err.Error())
	}
}

func createTempFile(t *testing.T, data string) string {
	t.Helper()

	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatalf("unable to create temp file: %s", err.Error())
	}
	defer f.Close()

	_, err = io.Copy(f, strings.NewReader(data))
	if err != nil {
		t.Fatalf("unable to write data to temp file: %s", err.Error())
	}

	return f.Name()
}

func testFetchBinary(t *testing.T) string {
	t.Helper()

	if path := os.Getenv("FETCH_BIN"); path != "" {
		abs, err := filepath.Abs(path)
		if err != nil {
			t.Fatalf("unable to resolve FETCH_BIN: %s", err.Error())
		}
		if _, err := os.Stat(abs); err != nil {
			t.Fatalf("FETCH_BIN is not usable: %s", err.Error())
		}
		return abs
	}

	return cargoBuild(t)
}

func cargoBuild(t *testing.T) string {
	t.Helper()

	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("unable to get current working directory: %s", err.Error())
	}
	mainPath := filepath.Dir(workingDir)

	cmd := exec.Command("cargo", "build", "--bin", "fetch")
	cmd.Dir = mainPath
	stderr := new(bytes.Buffer)
	cmd.Stderr = stderr
	if err = cmd.Run(); err != nil {
		t.Fatalf("unable to build Rust fetch binary: %s: %s", err.Error(), stderr.String())
	}

	return filepath.Join(mainPath, "target", "debug", getExeName())
}

func getExeName() string {
	if runtime.GOOS == "windows" {
		return "fetch.exe"
	}
	return "fetch"
}

func getFetchVersion(t *testing.T, path string) string {
	t.Helper()

	res := runFetch(t, path, "--version")
	assertExitCode(t, 0, res)

	_, version, ok := strings.Cut(res.stdout.String(), " ")
	if !ok {
		t.Fatalf("unexpected version output: %s", res.stdout.String())
	}
	version = strings.TrimSpace(version)

	if !strings.HasPrefix(version, "v") {
		t.Fatalf("version doesn't start with a 'v': %s", version)
	}
	if count := strings.Count(version, "."); count < 2 {
		t.Fatalf("invalid version format: %s", version)
	}

	return version
}

func startServer(h http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(h)
}

func startUDPDNSServer(t *testing.T, host string, ip net.IP) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Close()
	})

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			name, qtype, questionEnd, ok := parseDNSQuestion(buf[:n])
			if !ok {
				continue
			}

			var response bytes.Buffer
			response.Write(buf[:2])
			response.Write([]byte{0x81, 0x80})
			binary.Write(&response, binary.BigEndian, uint16(1))
			answer := name == host && qtype == 1 && ip.To4() != nil
			if answer {
				binary.Write(&response, binary.BigEndian, uint16(1))
			} else {
				binary.Write(&response, binary.BigEndian, uint16(0))
			}
			binary.Write(&response, binary.BigEndian, uint16(0))
			binary.Write(&response, binary.BigEndian, uint16(0))
			response.Write(buf[12:questionEnd])
			if answer {
				response.Write([]byte{0xc0, 0x0c})
				binary.Write(&response, binary.BigEndian, uint16(1))
				binary.Write(&response, binary.BigEndian, uint16(1))
				binary.Write(&response, binary.BigEndian, uint32(30))
				binary.Write(&response, binary.BigEndian, uint16(4))
				response.Write(ip.To4())
			}
			_, _ = conn.WriteTo(response.Bytes(), addr)
		}
	}()

	return conn.LocalAddr().String()
}

func parseDNSQuestion(raw []byte) (string, uint16, int, bool) {
	if len(raw) < 12 {
		return "", 0, 0, false
	}
	off := 12
	var labels []string
	for {
		if off >= len(raw) {
			return "", 0, 0, false
		}
		ln := int(raw[off])
		off++
		if ln == 0 {
			break
		}
		if ln&0xc0 != 0 || off+ln > len(raw) {
			return "", 0, 0, false
		}
		labels = append(labels, string(raw[off:off+ln]))
		off += ln
	}
	if off+4 > len(raw) {
		return "", 0, 0, false
	}
	name := "."
	if len(labels) > 0 {
		name = strings.Join(labels, ".") + "."
	}
	qtype := binary.BigEndian.Uint16(raw[off : off+2])
	return name, qtype, off + 4, true
}

func startSOCKS5Proxy(t *testing.T, targetAddr string) (string, <-chan string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 10)
	t.Cleanup(func() {
		ln.Close()
	})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSOCKS5ProxyConn(conn, targetAddr, seen)
		}
	}()

	return "socks5://" + ln.Addr().String(), seen
}

type http3TestServer struct {
	url        string
	caCertPath string
}

func startHTTP3Server(t *testing.T, handler http.Handler) http3TestServer {
	t.Helper()

	tlsDir := t.TempDir()
	caCert, caKey := generateCACert(t)
	serverCert, serverKey := generateCert(t, caCert, caKey, "http3-server")
	caCertPath := writeTempPEM(t, tlsDir, "http3-ca.crt", "CERTIFICATE", caCert.Raw)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{serverCert.Raw},
		PrivateKey:  serverKey,
		Leaf:        serverCert,
	}
	tlsConfig := http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, nil)
	if err != nil {
		t.Fatalf("unable to start HTTP/3 listener: %s", err.Error())
	}
	server3 := &http3.Server{Handler: handler}
	errCh := make(chan error, 1)
	go func() {
		if err := server3.ServeListener(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	t.Cleanup(func() {
		server3.Close()
		ln.Close()
		select {
		case err := <-errCh:
			t.Fatalf("HTTP/3 server error: %s", err.Error())
		default:
		}
	})

	return http3TestServer{
		url:        "https://" + ln.Addr().String(),
		caCertPath: caCertPath,
	}
}

func receiveHTTP3Request[T any](t *testing.T, ch <-chan T) T {
	t.Helper()

	select {
	case req := <-ch:
		return req
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for HTTP/3 request")
	}

	var zero T
	return zero
}

func handleSOCKS5ProxyConn(conn net.Conn, targetAddr string, seen chan<- string) {
	defer conn.Close()

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 || req[2] != 0x00 {
		writeSOCKS5Reply(conn, 0x07)
		return
	}

	host, err := readSOCKS5Host(conn, req[3])
	if err != nil {
		writeSOCKS5Reply(conn, 0x08)
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBytes))
	seen <- net.JoinHostPort(host, strconv.Itoa(port))

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		writeSOCKS5Reply(conn, 0x05)
		return
	}
	defer target.Close()

	if err := writeSOCKS5Reply(conn, 0x00); err != nil {
		return
	}

	go func() {
		io.Copy(target, conn)
		target.Close()
	}()
	io.Copy(conn, target)
}

func readSOCKS5Host(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		addr := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", err
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		return string(name), nil
	case 0x04:
		addr := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil
	default:
		return "", fmt.Errorf("unsupported SOCKS address type: %d", atyp)
	}
}

func writeSOCKS5Reply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func assertSOCKSProxyConnected(t *testing.T, seen <-chan string, want string) {
	t.Helper()

	select {
	case got := <-seen:
		if got != want {
			t.Fatalf("SOCKS proxy CONNECT target = %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("SOCKS proxy was not used")
	}
}

type reflectionGRPCServer struct {
	url        string
	caCertPath string
	cleanup    func()
}

func startReflectionGRPCServer(t *testing.T, useTLS, enableReflection bool) reflectionGRPCServer {
	t.Helper()

	handler := newReflectionGRPCHandler(t, enableReflection)
	server := httptest.NewUnstartedServer(handler)

	var caCertPath string
	var scheme string
	if useTLS {
		dir := t.TempDir()
		caCert, caKey := generateCACert(t)
		serverCert, serverKey := generateCert(t, caCert, caKey, "grpc-reflection")
		caCertPath = writeTempPEM(t, dir, "grpc-reflection-ca.crt", "CERTIFICATE", caCert.Raw)
		serverCertPath := writeTempPEM(t, dir, "grpc-reflection-server.crt", "CERTIFICATE", serverCert.Raw)
		serverKeyPath := writeTempPEM(t, dir, "grpc-reflection-server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))
		tlsCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
		if err != nil {
			t.Fatalf("LoadX509KeyPair: %v", err)
		}
		server.EnableHTTP2 = true
		server.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
		server.StartTLS()
		scheme = "https"
	} else {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		server.Config.Protocols = protocols
		server.Start()
		scheme = "http"
	}

	return reflectionGRPCServer{
		url:        scheme + "://" + server.Listener.Addr().String(),
		caCertPath: caCertPath,
		cleanup: func() {
			server.Close()
		},
	}
}

func writeHealthDescriptorSet(t *testing.T) string {
	t.Helper()

	fds := buildHealthDescriptorSet()
	data, err := protoMarshal.Marshal(fds)
	if err != nil {
		t.Fatalf("marshal descriptor set: %v", err)
	}

	path := filepath.Join(t.TempDir(), "grpc-health.pb")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write descriptor set: %v", err)
	}
	return path
}

func newReflectionGRPCHandler(t *testing.T, enableReflection bool) http.Handler {
	t.Helper()

	descriptorSet := buildHealthDescriptorSet()
	descriptorData, err := protoMarshal.Marshal(descriptorSet.File[0])
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc+proto")

		switch r.URL.Path {
		case "/grpc.health.v1.Health/Check":
			writeGRPCFrameResponse(w, buildHealthCheckResponse())
		case "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo":
			if !enableReflection {
				writeGRPCErrorResponse(w, "12", "reflection disabled")
				return
			}
			payload, ok := readSingleGRPCFrame(t, r.Body)
			if !ok {
				writeGRPCErrorResponse(w, "3", "invalid reflection request")
				return
			}
			resp, err := buildReflectionResponse(payload, descriptorData)
			if err != nil {
				writeGRPCErrorResponse(w, "5", err.Error())
				return
			}
			writeGRPCFrameResponse(w, resp)
		default:
			writeGRPCErrorResponse(w, "12", "unimplemented")
		}
	})
}

func buildHealthDescriptorSet() *descriptorpb.FileDescriptorSet {
	strType := descriptorpb.FieldDescriptorProto_TYPE_STRING
	enumType := descriptorpb.FieldDescriptorProto_TYPE_ENUM
	return &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			{
				Name:    ptr("grpc/health/v1/health.proto"),
				Package: ptr("grpc.health.v1"),
				Syntax:  ptr("proto3"),
				MessageType: []*descriptorpb.DescriptorProto{
					{
						Name: ptr("HealthCheckRequest"),
						Field: []*descriptorpb.FieldDescriptorProto{
							{
								Name:   ptr("service"),
								Number: ptr(int32(1)),
								Type:   &strType,
							},
						},
					},
					{
						Name: ptr("HealthCheckResponse"),
						Field: []*descriptorpb.FieldDescriptorProto{
							{
								Name:     ptr("status"),
								Number:   ptr(int32(1)),
								Type:     &enumType,
								TypeName: ptr(".grpc.health.v1.HealthCheckResponse.ServingStatus"),
							},
						},
						EnumType: []*descriptorpb.EnumDescriptorProto{
							{
								Name: ptr("ServingStatus"),
								Value: []*descriptorpb.EnumValueDescriptorProto{
									{Name: ptr("UNKNOWN"), Number: ptr(int32(0))},
									{Name: ptr("SERVING"), Number: ptr(int32(1))},
									{Name: ptr("NOT_SERVING"), Number: ptr(int32(2))},
									{Name: ptr("SERVICE_UNKNOWN"), Number: ptr(int32(3))},
								},
							},
						},
					},
				},
				Service: []*descriptorpb.ServiceDescriptorProto{
					{
						Name: ptr("Health"),
						Method: []*descriptorpb.MethodDescriptorProto{
							{
								Name:       ptr("Check"),
								InputType:  ptr(".grpc.health.v1.HealthCheckRequest"),
								OutputType: ptr(".grpc.health.v1.HealthCheckResponse"),
							},
						},
					},
				},
			},
		},
	}
}

func readSingleGRPCFrame(t *testing.T, body io.Reader) ([]byte, bool) {
	t.Helper()

	var header [5]byte
	if _, err := io.ReadFull(body, header[:]); err != nil {
		return nil, false
	}
	length := binary.BigEndian.Uint32(header[1:5])
	payload := make([]byte, length)
	if _, err := io.ReadFull(body, payload); err != nil {
		return nil, false
	}
	return payload, true
}

func buildHealthCheckResponse() []byte {
	var data []byte
	data = protowire.AppendTag(data, 1, protowire.VarintType)
	data = protowire.AppendVarint(data, 1)
	return data
}

func buildReflectionResponse(req []byte, descriptor []byte) ([]byte, error) {
	for len(req) > 0 {
		num, typ, n := protowire.ConsumeTag(req)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		req = req[n:]
		switch {
		case num == 7 && typ == protowire.BytesType:
			_, m := protowire.ConsumeString(req)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			return buildReflectionListResponse("grpc.health.v1.Health"), nil
		case num == 4 && typ == protowire.BytesType:
			symbol, m := protowire.ConsumeString(req)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			switch symbol {
			case "grpc.health.v1.Health",
				"grpc.health.v1.Health.Check",
				"grpc.health.v1.HealthCheckRequest",
				"grpc.health.v1.HealthCheckResponse":
				return buildReflectionDescriptorResponse(descriptor), nil
			default:
				return nil, fmt.Errorf("symbol not found: %s", symbol)
			}
		default:
			m := protowire.ConsumeFieldValue(num, typ, req)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			req = req[m:]
		}
	}
	return nil, errors.New("unsupported reflection request")
}

func buildReflectionListResponse(names ...string) []byte {
	var list []byte
	for _, name := range names {
		var service []byte
		service = protowire.AppendTag(service, 1, protowire.BytesType)
		service = protowire.AppendString(service, name)
		list = protowire.AppendTag(list, 1, protowire.BytesType)
		list = protowire.AppendBytes(list, service)
	}

	var resp []byte
	resp = protowire.AppendTag(resp, 6, protowire.BytesType)
	resp = protowire.AppendBytes(resp, list)
	return resp
}

func buildReflectionDescriptorResponse(descriptor []byte) []byte {
	var fdResp []byte
	fdResp = protowire.AppendTag(fdResp, 1, protowire.BytesType)
	fdResp = protowire.AppendBytes(fdResp, descriptor)

	var resp []byte
	resp = protowire.AppendTag(resp, 4, protowire.BytesType)
	resp = protowire.AppendBytes(resp, fdResp)
	return resp
}

func writeGRPCFrameResponse(w http.ResponseWriter, payload []byte) {
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	w.WriteHeader(http.StatusOK)
	w.Write(frame)
}

func writeGRPCErrorResponse(w http.ResponseWriter, status, message string) {
	w.Header().Set("Grpc-Status", status)
	w.Header().Set("Grpc-Message", message)
	w.WriteHeader(http.StatusOK)
}

func startUnixServer(path string, h http.HandlerFunc) (*httptest.Server, error) {
	server := httptest.NewUnstartedServer(h)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	server.Listener = l
	server.Start()
	return server, nil
}

func listFiles(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("unexpected error reading directory: %s", err.Error())
	}

	out := make([]string, len(entries))
	for i, entry := range entries {
		out[i] = entry.Name()
	}
	return out
}

func getModTime(t *testing.T, path string) time.Time {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("unable to get file info: %s", err.Error())
	}
	return info.ModTime()
}

func getOptionalModTime(t *testing.T, path string) *time.Time {
	t.Helper()

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("unable to get file info: %s", err.Error())
	}
	mt := info.ModTime()
	return &mt
}

func ptr[T any](v T) *T {
	return &v
}

func assertExitCode(t *testing.T, exp int, res runResult) {
	t.Helper()

	exitCode := res.state.ExitCode()
	if exp != exitCode {
		fmt.Printf("STDERR: %s\n", res.stderr.String())
		fmt.Printf("STDOUT: %s\n", res.stdout.String())
		t.Fatalf("unexpected exit code: %d", exitCode)
	}
}

func assertBufEmpty(t *testing.T, buf *bytes.Buffer) {
	t.Helper()

	if buf.Len() != 0 {
		t.Fatalf("unexpected data in buffer: %s", buf.String())
	}
}

func assertBufNotEmpty(t *testing.T, buf *bytes.Buffer) {
	t.Helper()

	if buf.Len() == 0 {
		t.Fatal("unexpected empty buffer")
	}
}

func assertBufContains(t *testing.T, buf *bytes.Buffer, s string) {
	t.Helper()

	if !strings.Contains(buf.String(), s) {
		t.Fatalf("unexpected buffer: %s", buf.String())
	}
}

func assertBufNotContains(t *testing.T, buf *bytes.Buffer, s string) {
	t.Helper()

	if strings.Contains(buf.String(), s) {
		t.Fatalf("unexpected buffer: %s", buf.String())
	}
}

func assertBufEquals(t *testing.T, buf *bytes.Buffer, s string) {
	t.Helper()

	if buf.String() != s {
		t.Fatalf("unexpected buffer: %s", buf.String())
	}
}

// syncBuffer is a thread-safe wrapper around bytes.Buffer.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// generateCACert generates a self-signed CA certificate for testing.
func generateCACert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate CA key: %s", err.Error())
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("unable to create CA cert: %s", err.Error())
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("unable to parse CA cert: %s", err.Error())
	}

	return caCert, caKey
}

// generateCert generates a certificate signed by the provided CA.
func generateCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, name string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate %s key: %s", name, err.Error())
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("unable to create %s cert: %s", name, err.Error())
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("unable to parse %s cert: %s", name, err.Error())
	}

	return cert, key
}

func createOCSPResponse(t *testing.T, issuer, leaf *x509.Certificate, issuerKey *rsa.PrivateKey, status int) []byte {
	t.Helper()

	response, err := ocsp.CreateResponse(issuer, leaf, ocsp.Response{
		Status:       status,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}, issuerKey)
	if err != nil {
		t.Fatalf("unable to create OCSP response: %s", err.Error())
	}
	return response
}

// writeTempPEM writes a PEM-encoded file to the temp directory.
func writeTempPEM(t *testing.T, dir, name, blockType string, data []byte) string {
	t.Helper()

	path := filepath.Join(dir, name)
	block := &pem.Block{Type: blockType, Bytes: data}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("unable to write %s: %s", name, err.Error())
	}
	return path
}

// startMTLSServer starts an HTTPS server that requires client certificates.
func startMTLSServer(t *testing.T, certPath, keyPath, caCertPath string) *httptest.Server {
	t.Helper()

	// Load server cert.
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("unable to load server cert: %s", err.Error())
	}

	// Load CA cert for client verification.
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("unable to read CA cert: %s", err.Error())
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("unable to add CA cert to pool")
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "mtls-success")
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	server.StartTLS()
	return server
}

// parseDigestAuthParams parses the parameters from a Digest Authorization header.
func parseDigestAuthParams(s string) map[string]string {
	params := make(map[string]string)
	for len(s) > 0 {
		s = strings.TrimSpace(s)
		if s == "" {
			break
		}
		key, rest, ok := strings.Cut(s, "=")
		if !ok {
			break
		}
		key = strings.TrimSpace(key)
		rest = strings.TrimSpace(rest)

		var value string
		if len(rest) > 0 && rest[0] == '"' {
			value, rest = parseDigestQuotedString(rest)
		} else {
			var val string
			val, rest, _ = strings.Cut(rest, ",")
			value = strings.TrimSpace(val)
		}
		params[strings.ToLower(key)] = value
		if len(rest) > 0 && rest[0] == ',' {
			rest = rest[1:]
		}
		s = rest
	}
	return params
}

func parseDigestQuotedString(s string) (string, string) {
	if len(s) == 0 || s[0] != '"' {
		return "", s
	}
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		if c == '"' {
			i++
			break
		}
		if c == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i += 2
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), s[i:]
}

func hashMD5(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}
