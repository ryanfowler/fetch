package integration_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(t *testing.T) {
	tempDir := getTempDir(t)
	defer os.RemoveAll(tempDir)

	fetchPath := goBuild(t, tempDir)
	version := getFetchVersion(t, fetchPath)

	t.Run("help", func(t *testing.T) {
		res := runFetch(t, fetchPath, "--help")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufNotEmpty(t, res.stdout)
	})

	t.Run("no url", func(t *testing.T) {
		res := runFetch(t, fetchPath)
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "<URL> must be provided")
	})

	t.Run("too many args", func(t *testing.T) {
		res := runFetch(t, fetchPath, "url1", "url2")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "unexpected argument")
	})

	t.Run("invalid flag", func(t *testing.T) {
		res := runFetch(t, fetchPath, "--invalid")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "unknown flag")
	})

	t.Run("conflicting flags", func(t *testing.T) {
		res := runFetch(t, fetchPath, "--basic", "user:pass", "--bearer", "token")
		assertExitCode(t, 1, res)
		assertBufEmpty(t, res.stdout)
		assertBufContains(t, res.stderr, "cannot be used together")
	})

	t.Run("verbosity", func(t *testing.T) {
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Custom-Header", "value")
			w.WriteHeader(200)
			io.WriteString(w, "hello")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL)
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "HTTP/1.1 200 OK")
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
		assertExitCode(t, 0, res)
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
		assertExitCode(t, 0, res)
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
		assertExitCode(t, 0, res)
	})

	t.Run("data", func(t *testing.T) {
		type requestData struct {
			body    string
			headers http.Header
		}
		chReq := make(chan requestData, 1)
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			var buf bytes.Buffer
			buf.ReadFrom(r.Body)
			chReq <- requestData{body: buf.String(), headers: r.Header}
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--data", "hello")
		assertExitCode(t, 0, res)
		req := <-chReq
		if req.body != "hello" {
			t.Fatalf("unexpected body: %s", req.body)
		}

		res = runFetch(t, fetchPath, server.URL, "--json", "--data", `{"key":"val"}`)
		assertExitCode(t, 0, res)
		req = <-chReq
		if req.body != `{"key":"val"}` {
			t.Fatalf("unexpected body: %s", req.body)
		}
		if h := req.headers.Get("Content-Type"); h != "application/json" {
			t.Fatalf("unexpected content-type: %s", h)
		}

		res = runFetch(t, fetchPath, server.URL, "--xml", "--data", `<Tag></Tag>`)
		assertExitCode(t, 0, res)
		req = <-chReq
		if req.body != `<Tag></Tag>` {
			t.Fatalf("unexpected body: %s", req.body)
		}
		if h := req.headers.Get("Content-Type"); h != "application/xml" {
			t.Fatalf("unexpected content-type: %s", h)
		}

		tempFile := createTempFile(t, "temp file data")
		defer os.Remove(tempFile)
		res = runFetch(t, fetchPath, server.URL, "--data", "@"+tempFile)
		assertExitCode(t, 0, res)
		req = <-chReq
		if req.body != "temp file data" {
			t.Fatalf("unexpected body: %s", req.body)
		}
	})

	t.Run("form", func(t *testing.T) {
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

	t.Run("multipart", func(t *testing.T) {
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
			file, err := form.File["file1"][0].Open()
			if err != nil {
				w.WriteHeader(400)
				io.WriteString(w, "cannot open form file: "+err.Error())
				return
			}

			var buf bytes.Buffer
			buf.ReadFrom(file)
			if buf.String() != "file content" {
				w.WriteHeader(400)
				io.WriteString(w, "invalid file content: "+buf.String())
				return
			}
		})
		defer server.Close()

		tempFile := createTempFile(t, "file content")
		defer os.Remove(tempFile)
		res := runFetch(t, fetchPath, server.URL, "-F", "key1=val1", "-F", "file1=@"+tempFile)
		assertExitCode(t, 0, res)
	})

	t.Run("output", func(t *testing.T) {
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
	})

	t.Run("timeout", func(t *testing.T) {
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
	})

	t.Run("ignore status", func(t *testing.T) {
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

	t.Run("server sent events", func(t *testing.T) {
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

	t.Run("update", func(t *testing.T) {
		var empty string
		var urlStr atomic.Pointer[string]
		urlStr.Store(&empty)
		var newVersion atomic.Pointer[string]
		newVersion.Store(&version)
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
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

			f, err := os.Open(fetchPath)
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

		os.Setenv("FETCH_INTERNAL_UPDATE_URL", server.URL)
		defer os.Unsetenv("FETCH_INTERNAL_UPDATE_URL")

		origModTime := getModTime(t, fetchPath)

		// Test update using latest version.
		res := runFetch(t, fetchPath, server.URL, "--update")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "currently using the latest version")
		if s := listFiles(t, filepath.Dir(fetchPath)); len(s) > 1 {
			t.Fatalf("unexpected files after updating: %v", s)
		}
		if !getModTime(t, fetchPath).Equal(origModTime) {
			t.Fatal("mod times after non-update are not equal")
		}

		// Test full update.
		newStr := "v(new)"
		newVersion.Store(&newStr)
		res = runFetch(t, fetchPath, server.URL, "--update")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "fetch successfully updated")
		if s := listFiles(t, filepath.Dir(fetchPath)); len(s) > 1 {
			t.Fatalf("unexpected files after updating: %v", s)
		}
		// Verify that the mod time has changed on the file.
		afterModTime := getModTime(t, fetchPath)
		if origModTime.Equal(afterModTime) {
			t.Fatal("mod times are equal")
		}

		// Ensure the new fetch binary still works.
		res = runFetch(t, fetchPath, "--version")
		assertExitCode(t, 0, res)
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

func goBuild(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, getExeName())
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
