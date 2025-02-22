package integration_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestMain(t *testing.T) {
	tempDir := getTempDir(t)
	defer os.RemoveAll(tempDir)

	fetchPath := goBuild(t, tempDir)
	_ = getFetchVersion(t, fetchPath)

	t.Run("help", func(t *testing.T) {
		res := runFetch(t, fetchPath, "--help")
		assertExitCode(t, 0, res.state)
		assertBufEmpty(t, res.stderr)
		assertBufNotEmpty(t, res.stdout)
	})

	t.Run("no url", func(t *testing.T) {
		res := runFetch(t, fetchPath)
		assertExitCode(t, 1, res.state)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "<URL> must be provided")
	})

	t.Run("too many args", func(t *testing.T) {
		res := runFetch(t, fetchPath, "url1", "url2")
		assertExitCode(t, 1, res.state)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "unexpected argument")
	})

	t.Run("invalid flag", func(t *testing.T) {
		res := runFetch(t, fetchPath, "--invalid")
		assertExitCode(t, 1, res.state)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "unknown flag")
	})

	t.Run("conflicting flags", func(t *testing.T) {
		res := runFetch(t, fetchPath, "--basic", "user:pass", "--bearer", "token")
		assertExitCode(t, 1, res.state)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "cannot be used together")
	})

	t.Run("200 verbosity", func(t *testing.T) {
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Custom-Header", "value")
			w.WriteHeader(200)
			io.WriteString(w, "hello")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL)
		assertExitCode(t, 0, res.state)
		assertBufContains(t, res.stderr, "HTTP/1.1 200 OK")
		assertBufNotContains(t, res.stderr, "user-agent")
		assertBufNotContains(t, res.stderr, "x-custom-header")
		assertBufEquals(t, res.stdout, "hello")

		res = runFetch(t, fetchPath, server.URL, "-s")
		assertExitCode(t, 0, res.state)
		assertBufEmpty(t, res.stderr)
		assertBufEquals(t, res.stdout, "hello")

		res = runFetch(t, fetchPath, server.URL, "-v")
		assertExitCode(t, 0, res.state)
		assertBufNotContains(t, res.stderr, "user-agent")
		assertBufContains(t, res.stderr, "x-custom-header")
		assertBufEquals(t, res.stdout, "hello")

		res = runFetch(t, fetchPath, server.URL, "-vv")
		assertExitCode(t, 0, res.state)
		assertBufContains(t, res.stderr, "GET / HTTP/1.1")
		assertBufContains(t, res.stderr, "user-agent")
		assertBufContains(t, res.stderr, "x-custom-header")
		assertBufEquals(t, res.stdout, "hello")
	})

	t.Run("aws-sigv4 auth", func(t *testing.T) {
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
			if amzSha != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
				w.WriteHeader(400)
				return
			}
		})
		defer server.Close()

		os.Setenv("AWS_ACCESS_KEY_ID", "1234")
		os.Setenv("AWS_SECRET_ACCESS_KEY", "5678")
		res := runFetch(t, fetchPath, server.URL, "--aws-sigv4", "us-east-1/s3")
		os.Unsetenv("AWS_ACCESS_KEY_ID")
		os.Unsetenv("AWS_SECRET_ACCESS_KEY")
		assertExitCode(t, 0, res.state)
	})

	t.Run("basic auth", func(t *testing.T) {
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
		assertExitCode(t, 0, res.state)
	})

	t.Run("bearer auth", func(t *testing.T) {
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
		assertExitCode(t, 0, res.state)
	})
}

type runResult struct {
	state  *os.ProcessState
	stderr *bytes.Buffer
	stdout *bytes.Buffer
}

func runFetch(t *testing.T, path string, args ...string) runResult {
	t.Helper()

	var stderr, stdout = new(bytes.Buffer), new(bytes.Buffer)
	cmd := exec.Command(path, args...)
	cmd.Stderr = stderr
	cmd.Stdout = stdout
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("unexpected error running the fetch command: %s", err.Error())
		}
	}
	return runResult{
		state:  cmd.ProcessState,
		stderr: stderr,
		stdout: stdout,
	}
}

func getTempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("unable to make temp dir: %s", err.Error())
	}

	return dir
}

func goBuild(t *testing.T, dir string) string {
	t.Helper()

	name := "fetch"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("unable to get current working directory: %s", err.Error())
	}
	mainPath := filepath.Dir(workingDir)

	cmd := exec.Command("go",
		"build",
		"-o", path,
		"-trimpath",
		mainPath,
	)
	stderr := new(bytes.Buffer)
	cmd.Stderr = stderr
	if err = cmd.Run(); err != nil {
		t.Fatalf("unable to build fetch binary: %s: %s", err.Error(), stderr.String())
	}

	return path
}

func getFetchVersion(t *testing.T, path string) string {
	t.Helper()

	res := runFetch(t, path, "--version")
	assertExitCode(t, 0, res.state)

	_, version, ok := strings.Cut(res.stdout.String(), " ")
	if !ok {
		t.Fatalf("unexpected version output: %s", res.stdout.String())
	}
	version = strings.TrimSpace(version)

	split := strings.Split(version, ".")
	if len(split) != 3 {
		t.Fatalf("invalid version format: %s", version)
	}
	for _, n := range split {
		_, err := strconv.Atoi(n)
		if err != nil {
			t.Fatalf("invalid version format: %s", version)
		}
	}

	return version
}

func startServer(h http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(h)
}

func assertExitCode(t *testing.T, exp int, state *os.ProcessState) {
	t.Helper()

	exitCode := state.ExitCode()
	if exp != exitCode {
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
