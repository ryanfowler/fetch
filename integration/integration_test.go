package integration_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"

	"github.com/coder/websocket"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/encoding/protowire"
	protoMarshal "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
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
		assertBufContains(t, res.stderr, "> GET / HTTP/1.1")
		assertBufContains(t, res.stderr, "> user-agent")
		assertBufContains(t, res.stderr, "< x-custom-header")
		assertBufContains(t, res.stderr, "< HTTP/1.1 200 OK")
		assertBufNotContains(t, res.stderr, "* ")
		assertBufEquals(t, res.stdout, "hello")

		res = runFetch(t, fetchPath, server.URL, "-vvv")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "> GET / HTTP/1.1")
		assertBufContains(t, res.stderr, "< HTTP/1.1 200 OK")
		assertBufContains(t, res.stderr, "* TCP:")
		assertBufContains(t, res.stderr, "* TTFB:")
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

	t.Run("http version", func(t *testing.T) {
		server := startServer(func(w http.ResponseWriter, r *http.Request) {})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--http", "1")
		assertExitCode(t, 0, res)

		res = runFetch(t, fetchPath, server.URL, "--http", "2")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "http2:")
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

	t.Run("remote-name ignores content-disposition", func(t *testing.T) {
		const data = "file content"
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Disposition", `attachment; filename="cd-filename.txt"`)
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

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

		// -O should use URL path, NOT Content-Disposition
		urlStr := server.URL + "/url-filename.txt"
		res := runFetch(t, fetchPath, urlStr, "-O")
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
		const data = "file content"
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Disposition", `attachment; filename="cd-filename.txt"`)
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

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

		// -O -J should use Content-Disposition
		urlStr := server.URL + "/url-filename.txt"
		res := runFetch(t, fetchPath, urlStr, "-O", "-J")
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
		res := runFetch(t, fetchPath, "http://example.com", "-J")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "flag '--remote-header-name' requires '--remote-name'")
	})

	t.Run("file exists error", func(t *testing.T) {
		const data = "file content"
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

		wd, err := os.Getwd()
		if err != nil {
			t.Fatalf("unable to get current dir: %s", err.Error())
		}
		err = os.Chdir(dir)
		if err != nil {
			t.Fatalf("unable to change current dir: %s", err.Error())
		}
		defer os.Chdir(wd)

		// Create existing file
		existingPath := filepath.Join(dir, "existing.txt")
		if err := os.WriteFile(existingPath, []byte("old content"), 0644); err != nil {
			t.Fatalf("unable to create existing file: %s", err.Error())
		}

		// Attempt to overwrite without --clobber should fail
		urlStr := server.URL + "/existing.txt"
		res := runFetch(t, fetchPath, urlStr, "-O")
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

	t.Run("clobber overwrites existing file", func(t *testing.T) {
		const data = "new content"
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

		wd, err := os.Getwd()
		if err != nil {
			t.Fatalf("unable to get current dir: %s", err.Error())
		}
		err = os.Chdir(dir)
		if err != nil {
			t.Fatalf("unable to change current dir: %s", err.Error())
		}
		defer os.Chdir(wd)

		// Create existing file
		existingPath := filepath.Join(dir, "existing.txt")
		if err := os.WriteFile(existingPath, []byte("old content"), 0644); err != nil {
			t.Fatalf("unable to create existing file: %s", err.Error())
		}

		// Overwrite with --clobber should succeed
		urlStr := server.URL + "/existing.txt"
		res := runFetch(t, fetchPath, urlStr, "-O", "--clobber")
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
		const data = "file content"
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			// Attempt path traversal in Content-Disposition header
			w.Header().Set("Content-Disposition", `attachment; filename="../../../tmp/malicious.txt"`)
			w.WriteHeader(200)
			io.WriteString(w, data)
		})
		defer server.Close()

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

		// -O -J with path traversal in Content-Disposition should sanitize to base name
		urlStr := server.URL + "/fallback.txt"
		res := runFetch(t, fetchPath, urlStr, "-O", "-J")
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

	t.Run("unix socket", func(t *testing.T) {
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

		sock := filepath.Join(tempDir, "server.sock")
		defer os.Remove(sock)

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

		// Redirect at -vv shows prefixed request/response for each hop.
		count.Store(1)
		res = runFetch(t, fetchPath, server.URL, "-vv")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "> GET / HTTP/1.1")
		assertBufContains(t, res.stderr, "< HTTP/1.1 301 Moved Permanently")
		assertBufContains(t, res.stderr, "< HTTP/1.1 200 OK")
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

	t.Run("gzip compression", func(t *testing.T) {
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
	})

	t.Run("connect rpc error response", func(t *testing.T) {
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
		// Build a FileDescriptorSet with a client-streaming method.
		boolTrue := true
		strType := descriptorpb.FieldDescriptorProto_TYPE_STRING
		int64Type := descriptorpb.FieldDescriptorProto_TYPE_INT64
		fds := &descriptorpb.FileDescriptorSet{
			File: []*descriptorpb.FileDescriptorProto{
				{
					Name:    strPtr("stream.proto"),
					Package: strPtr("streampkg"),
					Syntax:  strPtr("proto3"),
					MessageType: []*descriptorpb.DescriptorProto{
						{
							Name: strPtr("StreamRequest"),
							Field: []*descriptorpb.FieldDescriptorProto{
								{
									Name:   strPtr("value"),
									Number: int32Ptr(1),
									Type:   &strType,
								},
							},
						},
						{
							Name: strPtr("StreamResponse"),
							Field: []*descriptorpb.FieldDescriptorProto{
								{
									Name:   strPtr("count"),
									Number: int32Ptr(1),
									Type:   &int64Type,
								},
							},
						},
					},
					Service: []*descriptorpb.ServiceDescriptorProto{
						{
							Name: strPtr("StreamService"),
							Method: []*descriptorpb.MethodDescriptorProto{
								{
									Name:            strPtr("ClientStream"),
									InputType:       strPtr(".streampkg.StreamRequest"),
									OutputType:      strPtr(".streampkg.StreamResponse"),
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
		defer server.Close()

		t.Run("multiple messages", func(t *testing.T) {
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
			res := runFetch(t, fetchPath,
				server.URL+"/streampkg.StreamService/ClientStream",
				"--grpc", "--proto-desc", descFile,
				"--http", "1", "--format", "on")
			assertExitCode(t, 0, res)
		})
	})

	t.Run("proto flags mutual exclusivity", func(t *testing.T) {
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
		res := runFetch(t, fetchPath, "http://example.com/svc/Method", "--grpc", "--proto-desc", "/nonexistent/file.pb")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "does not exist")
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
		assertBufContains(t, res.stderr, "Already using the latest version")
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
		assertBufContains(t, res.stderr, "Updated fetch:")
		assertBufContains(t, res.stderr, "Changelog:")
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

		// Test dry-run update when already on latest version.
		newVersion.Store(&version)
		dryRunModTime := getModTime(t, fetchPath)
		res = runFetch(t, fetchPath, server.URL, "--update", "--dry-run")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "Already using the latest version")
		if !getModTime(t, fetchPath).Equal(dryRunModTime) {
			t.Fatal("binary was modified during dry-run update (same version)")
		}

		// Test dry-run update when a new version is available.
		newVersion.Store(&newStr)
		dryRunModTime = getModTime(t, fetchPath)
		res = runFetch(t, fetchPath, server.URL, "--update", "--dry-run")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "Update available")
		assertBufContains(t, res.stderr, newStr)
		assertBufNotContains(t, res.stderr, "Updated fetch:")
		assertBufNotContains(t, res.stderr, "Downloading")
		if !getModTime(t, fetchPath).Equal(dryRunModTime) {
			t.Fatal("binary was modified during dry-run update")
		}

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

	t.Run("mtls", func(t *testing.T) {
		// Generate test CA, server cert, and client cert.
		caCert, caKey := generateCACert(t)
		serverCert, serverKey := generateCert(t, caCert, caKey, "server")
		clientCert, clientKey := generateCert(t, caCert, caKey, "client")

		// Write certs to temp files.
		caCertPath := writeTempPEM(t, tempDir, "ca.crt", "CERTIFICATE", caCert.Raw)
		serverCertPath := writeTempPEM(t, tempDir, "server.crt", "CERTIFICATE", serverCert.Raw)
		serverKeyPath := writeTempPEM(t, tempDir, "server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))
		clientCertPath := writeTempPEM(t, tempDir, "client.crt", "CERTIFICATE", clientCert.Raw)
		clientKeyPath := writeTempPEM(t, tempDir, "client.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))

		// Create combined cert+key file.
		combinedPath := filepath.Join(tempDir, "client-combined.pem")
		combinedData := append(
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw}),
			pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})...,
		)
		if err := os.WriteFile(combinedPath, combinedData, 0600); err != nil {
			t.Fatalf("unable to write combined pem: %s", err.Error())
		}

		// Create mTLS server.
		server := startMTLSServer(t, serverCertPath, serverKeyPath, caCertPath)
		defer server.Close()

		t.Run("successful mtls with separate cert and key", func(t *testing.T) {
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
			res := runFetch(t, fetchPath, server.URL,
				"--ca-cert", caCertPath,
				"--cert", combinedPath,
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "200 OK")
			assertBufEquals(t, res.stdout, "mtls-success")
		})

		t.Run("missing client cert fails", func(t *testing.T) {
			res := runFetch(t, fetchPath, server.URL,
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 1, res)
			// Server requires client cert, so connection should fail.
			assertBufContains(t, res.stderr, "error")
		})

		t.Run("cert without key fails", func(t *testing.T) {
			res := runFetch(t, fetchPath, server.URL,
				"--ca-cert", caCertPath,
				"--cert", clientCertPath,
			)
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "may require a private key")
		})

		t.Run("key without cert fails", func(t *testing.T) {
			res := runFetch(t, fetchPath, server.URL,
				"--ca-cert", caCertPath,
				"--key", clientKeyPath,
			)
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "'--key' requires '--cert'")
		})

		t.Run("cert file not found", func(t *testing.T) {
			res := runFetch(t, fetchPath, server.URL,
				"--cert", "/nonexistent/client.crt",
				"--key", clientKeyPath,
			)
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "does not exist")
		})

		t.Run("key file not found", func(t *testing.T) {
			res := runFetch(t, fetchPath, server.URL,
				"--cert", clientCertPath,
				"--key", "/nonexistent/client.key",
			)
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "does not exist")
		})
	})

	t.Run("inspect-tls", func(t *testing.T) {
		// Generate test CA and server cert with SANs.
		caCert, caKey := generateCACert(t)
		serverCert, serverKey := generateCert(t, caCert, caKey, "test-server")
		caCertPath := writeTempPEM(t, tempDir, "inspect-ca.crt", "CERTIFICATE", caCert.Raw)
		serverCertPath := writeTempPEM(t, tempDir, "inspect-server.crt", "CERTIFICATE", serverCert.Raw)
		serverKeyPath := writeTempPEM(t, tempDir, "inspect-server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))

		// Start a TLS server.
		tlsCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
		if err != nil {
			t.Fatalf("unable to load server cert: %s", err.Error())
		}
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "tls-body")
		}))
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		}
		server.StartTLS()
		defer server.Close()

		t.Run("shows certificate chain", func(t *testing.T) {
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
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "TLS 1.3")
		})

		t.Run("shows SANs", func(t *testing.T) {
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "SANs:")
			assertBufContains(t, res.stderr, "localhost")
		})

		t.Run("shows expiry info", func(t *testing.T) {
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--ca-cert", caCertPath,
			)
			assertExitCode(t, 0, res)
			// The test cert expires in 1 hour, so < 1 day.
			assertBufContains(t, res.stderr, "expires in <1 day")
		})

		t.Run("works with insecure flag", func(t *testing.T) {
			res := runFetch(t, fetchPath, server.URL,
				"--inspect-tls",
				"--insecure",
			)
			assertExitCode(t, 0, res)
			assertBufContains(t, res.stderr, "Certificate chain")
			assertBufContains(t, res.stderr, "test-server")
		})

		t.Run("rejects http url", func(t *testing.T) {
			httpServer := startServer(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "ok")
			})
			defer httpServer.Close()

			res := runFetch(t, fetchPath, httpServer.URL, "--inspect-tls")
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "--inspect-tls requires an HTTPS URL")
		})

		t.Run("works with verbose flag", func(t *testing.T) {
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

	t.Run("session", func(t *testing.T) {
		sessDir := filepath.Join(tempDir, "sessions")
		os.MkdirAll(sessDir, 0755)
		os.Setenv("FETCH_INTERNAL_SESSIONS_DIR", sessDir)
		defer os.Unsetenv("FETCH_INTERNAL_SESSIONS_DIR")

		t.Run("cookies persist across requests", func(t *testing.T) {
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
			res := runFetch(t, fetchPath, server.URL+"/login", "--session", "integ-test")
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "logged in")

			// Second request: cookie is sent automatically.
			res = runFetch(t, fetchPath, server.URL+"/dashboard", "--session", "integ-test")
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "welcome")

			// Without session: cookie is NOT sent.
			res = runFetch(t, fetchPath, server.URL+"/dashboard")
			assertExitCode(t, 4, res)
			assertBufEquals(t, res.stdout, "unauthorized")
		})

		t.Run("expired cookies are not sent", func(t *testing.T) {
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

			res := runFetch(t, fetchPath, server.URL+"/set", "--session", "expiry-integ")
			assertExitCode(t, 0, res)

			res = runFetch(t, fetchPath, server.URL+"/check", "--session", "expiry-integ")
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "ok")
		})

		t.Run("different session names are isolated", func(t *testing.T) {
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
			res := runFetch(t, fetchPath, server.URL+"/set?v=alpha", "--session", "sess-a")
			assertExitCode(t, 0, res)

			res = runFetch(t, fetchPath, server.URL+"/set?v=beta", "--session", "sess-b")
			assertExitCode(t, 0, res)

			// Verify sessions are isolated.
			res = runFetch(t, fetchPath, server.URL+"/get", "--session", "sess-a")
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "alpha")

			res = runFetch(t, fetchPath, server.URL+"/get", "--session", "sess-b")
			assertExitCode(t, 0, res)
			assertBufEquals(t, res.stdout, "beta")
		})

		t.Run("invalid session name rejected", func(t *testing.T) {
			res := runFetch(t, fetchPath, "http://example.com", "--session", "../evil")
			assertExitCode(t, 1, res)
			assertBufContains(t, res.stderr, "session")
		})
	})

	t.Run("copy", func(t *testing.T) {
		t.Run("stdout still has body", func(t *testing.T) {
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
			server := startServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
			})
			defer server.Close()

			res := runFetch(t, fetchPath, "--copy", "-m", "HEAD", server.URL)
			assertExitCode(t, 0, res)
			assertBufEmpty(t, res.stdout)
		})

		t.Run("copy with silent mode", func(t *testing.T) {
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

	t.Run("retry on 503", func(t *testing.T) {
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

		res := runFetch(t, fetchPath, server.URL, "--retry", "3", "--retry-delay", "0.01")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
		assertBufContains(t, res.stderr, "retry")
		if count.Load() != 3 {
			t.Fatalf("expected 3 requests, got %d", count.Load())
		}
	})

	t.Run("retry on 502", func(t *testing.T) {
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

		res := runFetch(t, fetchPath, server.URL, "--retry", "2", "--retry-delay", "0.01")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "recovered")
	})

	t.Run("retry on 504", func(t *testing.T) {
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

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", "0.01")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("retry on 429", func(t *testing.T) {
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

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", "0.01")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("no retry on 404", func(t *testing.T) {
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			w.WriteHeader(404)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "3", "--retry-delay", "0.01")
		assertExitCode(t, 4, res)
		assertBufNotContains(t, res.stderr, "retry")
		if count.Load() != 1 {
			t.Fatalf("expected 1 request (no retries), got %d", count.Load())
		}
	})

	t.Run("no retry on 200", func(t *testing.T) {
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "3", "--retry-delay", "0.01")
		assertExitCode(t, 0, res)
		if count.Load() != 1 {
			t.Fatalf("expected 1 request, got %d", count.Load())
		}
	})

	t.Run("retry exhausted", func(t *testing.T) {
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			w.WriteHeader(503)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "2", "--retry-delay", "0.01")
		assertExitCode(t, 5, res)
		if count.Load() != 3 { // 1 initial + 2 retries
			t.Fatalf("expected 3 requests, got %d", count.Load())
		}
	})

	t.Run("retry with request body", func(t *testing.T) {
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

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", "0.01",
			"-d", "test-body")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
		if *lastBody.Load() != "test-body" {
			t.Fatalf("body not replayed correctly: %s", *lastBody.Load())
		}
	})

	t.Run("retry silent", func(t *testing.T) {
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

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", "0.01", "-s")
		assertExitCode(t, 0, res)
		assertBufEmpty(t, res.stderr)
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("retry verbose", func(t *testing.T) {
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

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", "0.01", "-v")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "retry")
		assertBufNotContains(t, res.stderr, "* retry")
		assertBufContains(t, res.stderr, "200 OK")
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("retry verbose vv", func(t *testing.T) {
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

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", "0.01", "-vv")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "* retry")
		assertBufContains(t, res.stderr, "> GET / HTTP/1.1")
		assertBufContains(t, res.stderr, "< HTTP/1.1 200 OK")
		assertBufEquals(t, res.stdout, "ok")
	})

	t.Run("no retry on redirect limit exceeded", func(t *testing.T) {
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			// Always redirect to self.
			http.Redirect(w, r, r.URL.Path, http.StatusFound)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "2", "--retry-delay", "0.01", "--redirects", "1")
		assertExitCode(t, 1, res)
		assertBufNotContains(t, res.stderr, "retry")
		assertBufContains(t, res.stderr, "exceeded maximum number of redirects")
	})

	t.Run("retry 0 no retry", func(t *testing.T) {
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			w.WriteHeader(503)
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "0", "--retry-delay", "0.01")
		assertExitCode(t, 5, res)
		if count.Load() != 1 {
			t.Fatalf("expected 1 request, got %d", count.Load())
		}
	})

	t.Run("sniff json without content-type", func(t *testing.T) {
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
		res := runFetch(t, fetchPath, "--grpc", "ws://localhost:1234")
		assertExitCode(t, 1, res)
		assertBufContains(t, res.stderr, "cannot be used together")
	})

	t.Run("websocket non-GET method warns", func(t *testing.T) {
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
		res := runFetch(t, fetchPath, "--dry-run", "ws://localhost:1234/chat")
		assertExitCode(t, 0, res)
		assertBufContains(t, res.stderr, "GET")
		assertBufContains(t, res.stderr, "/chat")
	})

	t.Run("websocket ctrl-c exits", func(t *testing.T) {
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

	t.Run("retry on per-attempt timeout", func(t *testing.T) {
		var count atomic.Int64
		server := startServer(func(w http.ResponseWriter, r *http.Request) {
			n := count.Add(1)
			if n <= 1 {
				// First attempt: delay longer than the per-attempt timeout.
				time.Sleep(2 * time.Second)
			}
			io.WriteString(w, "ok")
		})
		defer server.Close()

		res := runFetch(t, fetchPath, server.URL, "--retry", "1", "--retry-delay", "0.01", "--timeout", "0.5")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
		if count.Load() != 2 {
			t.Fatalf("expected 2 requests, got %d", count.Load())
		}
	})

	t.Run("timing waterfall", func(t *testing.T) {
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

		res := runFetch(t, fetchPath, server.URL, "--timing", "--retry", "1", "--retry-delay", "0.01")
		assertExitCode(t, 0, res)
		assertBufEquals(t, res.stdout, "ok")
		assertBufContains(t, res.stderr, "Total")
		assertBufContains(t, res.stderr, "█")
	})

	t.Run("timing waterfall websocket warning", func(t *testing.T) {
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

func strPtr(s string) *string { return &s }
func int32Ptr(i int32) *int32 { return &i }
