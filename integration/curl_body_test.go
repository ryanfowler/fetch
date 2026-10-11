package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFromCurlBodyOptionSemantics(t *testing.T) {
	fetchPath := fetchExecutable(t)
	payload := "a\r\nb\x00c\n"
	for _, tt := range []struct {
		name, options, want string
		stdin, redirect     bool
	}{
		{name: "text file", options: "--data @body.bin", want: "abc"},
		{name: "ascii file", options: "--data-ascii @body.bin", want: "abc"},
		{name: "binary file", options: "--data-binary @body.bin", want: payload},
		{name: "JSON file", options: "--json @body.bin", want: payload},
		{name: "JSON fragments", options: `--json '{"a":' --json '1}'`, want: `{"a":1}`},
		{name: "text stdin", options: "-d @-", want: "abc", stdin: true},
		{name: "binary stdin", options: "--data-binary @-", want: payload, stdin: true},
		{name: "JSON stdin", options: "--json @-", want: payload, stdin: true},
		{name: "mixed file options", options: "-d @body.bin --data-binary @body.bin", want: "abc&" + payload},
		{name: "text file redirect replay", options: "-L -d @body.bin", want: "abc", redirect: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "body.bin"), []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			var hits atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				data, err := io.ReadAll(io.LimitReader(r.Body, 1024))
				if err != nil || string(data) != tt.want || r.Method != http.MethodPost {
					t.Errorf("method=%s, body=%q, error=%v; want POST, %q", r.Method, data, err, tt.want)
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				if tt.redirect && r.URL.Path == "/start" {
					http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
					return
				}
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, "ok")
			}))
			server.Config.ReadTimeout = 5 * time.Second
			server.Config.WriteTimeout = 5 * time.Second
			server.Start()
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := fmt.Sprintf("curl --silent --max-time 10 %s %s/start", tt.options, server.URL)
			cmd := exec.CommandContext(ctx, fetchPath, "--auto-update", "false", "--from-curl", command)
			cmd.WaitDelay = time.Second
			cmd.Dir = root
			cmd.Env = append(os.Environ(),
				"HOME="+root, "USERPROFILE="+root,
				"XDG_CONFIG_HOME="+root, "XDG_CACHE_HOME="+root,
				"APPDATA="+root, "LOCALAPPDATA="+root,
				"TMPDIR="+root, "TMP="+root, "TEMP="+root,
				"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "NO_PROXY=*",
				"http_proxy=", "https_proxy=", "all_proxy=", "no_proxy=*",
			)
			if tt.stdin {
				cmd.Stdin = strings.NewReader(payload)
			}
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("fetch: %v, stdout=%q, stderr=%q", err, stdout.String(), stderr.String())
			}
			if stdout.String() != "ok" || stderr.Len() != 0 {
				t.Fatalf("stdout=%q, stderr=%q; want ok and empty stderr", stdout.String(), stderr.String())
			}
			wantHits := int64(1)
			if tt.redirect {
				wantHits++
			}
			if got := hits.Load(); got != wantHits {
				t.Fatalf("requests = %d, want %d", got, wantHits)
			}
		})
	}
}
