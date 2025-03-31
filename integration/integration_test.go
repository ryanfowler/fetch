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
	"net"
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

	"github.com/ryanfowler/fetch/internal/core"
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
			w.WriteHeader(200)
			io.WriteString(w, amzSha)
		})
		defer server.Close()

		os.Setenv("AWS_ACCESS_KEY_ID", "1234")
		defer os.Unsetenv("AWS_ACCESS_KEY_ID")
		os.Setenv("AWS_SECRET_ACCESS_KEY", "5678")
		defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")

		// No request body.
		res := runFetch(t, fetchPath, server.URL, "--aws-sigv4", "us-east-1/s3")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

		// Direct request body.
		res = runFetch(t, fetchPath, server.URL, "--aws-sigv4=us-east-1/s3", "-d", "data")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7")

		// Body from file.
		temp := createTempFile(t, "data")
		defer os.Remove(temp)
		res = runFetch(t, fetchPath, server.URL, "--aws-sigv4=us-east-1/s3", "-d", "@"+temp)
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7")

		// Body from stdin.
		res = runFetchStdin(t, "data", fetchPath, server.URL, "--aws-sigv4=us-east-1/s3", "-d", "@-")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "UNSIGNED-PAYLOAD")
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
		// Files should include content-length.
		if req.contentLength != int64(len(fileContent)) {
			t.Fatalf("unexpected content-length: %d", req.contentLength)
		}

	})

	t.Run("dns over https", func(t *testing.T) {
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/dns-query" {
				io.WriteString(w, `{"Status":0,"Answer":[{"data":"127.0.0.1"}]}`)
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

	t.Run("output-current-dir", func(t *testing.T) {
		const data = "this is the current dir data"
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

		// Change the working directory to a temp one.
		dir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Fatalf("unable to create temp dir: %s", err.Error())
		}
		defer os.RemoveAll(dir)

		wd, err := os.Getwd()
		if err != nil {
			t.Fatalf("unable to get current dir: %s", err.Error())
		}
		err = os.Chdir(dir)
		if err != nil {
			t.Fatalf("unable to change current dir: %s", err.Error())
		}
		defer os.Chdir(wd)

		urlStr := server.URL + "/dir/path_to_file.txt"
		res := runFetch(t, fetchPath, urlStr, "-O")
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

	t.Run("range request", func(t *testing.T) {
		var expectedRange atomic.Pointer[string]
		expectedRange.Store(core.PointerTo(""))
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
		expectedRange.Store(core.PointerTo("bytes=-1023"))
		res = runFetch(t, fetchPath, server.URL, "--range", "-1023")
		assertExitCode(t, 0, res)

		// Range header with no end.
		expectedRange.Store(core.PointerTo("bytes=1023-"))
		res = runFetch(t, fetchPath, server.URL, "--range", "1023-")
		assertExitCode(t, 0, res)

		// Range header with start and end.
		expectedRange.Store(core.PointerTo("bytes=0-1023"))
		res = runFetch(t, fetchPath, server.URL, "--range", "0-1023")
		assertExitCode(t, 0, res)

		// Multiple ranges.
		expectedRange.Store(core.PointerTo("bytes=0-1023, 2047-3070"))
		res = runFetch(t, fetchPath, server.URL, "-r", "0-1023", "-r", "2047-3070")
		assertExitCode(t, 0, res)
	})

	t.Run("redirects", func(t *testing.T) {
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

		// Test the auto-update functionality.
		res = runFetch(t, fetchPath, "--version", "--auto-update", "0s")
		assertExitCode(t, 0, res)
		var n int
		for {
			mt := getOptionalModTime(t, fetchPath)
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
	return runFetchStdin(t, "", path, args...)
}

func runFetchStdin(t *testing.T, input, path string, args ...string) runResult {
	t.Helper()

	var stderr, stdout = new(bytes.Buffer), new(bytes.Buffer)
	cmd := exec.Command(path, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
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
