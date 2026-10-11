package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestFetchCancelsBlockedRequestPreparation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Input copying must be canceled before this editor could be launched.
	t.Setenv("VISUAL", executable)
	fds := createDescribeTestDescriptorSet()
	fds.File[0].Service = []*descriptorpb.ServiceDescriptorProto{{
		Name: new("TestService"),
		Method: []*descriptorpb.MethodDescriptorProto{
			{Name: new("Call"), InputType: new(".testpkg.TestMessage"), OutputType: new(".testpkg.TestMessage")},
			{Name: new("Stream"), InputType: new(".testpkg.TestMessage"), OutputType: new(".testpkg.TestMessage"), ClientStreaming: new(true)},
		},
	}}
	descriptors, err := proto.Marshal(fds)
	if err != nil {
		t.Fatal(err)
	}
	descriptorPath := filepath.Join(t.TempDir(), "service.pb")
	if err := os.WriteFile(descriptorPath, descriptors, 0o600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	tests := []struct {
		name         string
		aws          bool
		json         bool
		dryRun       bool
		clientStream bool
		edit         bool
	}{
		{name: "AWS materialization", aws: true},
		{name: "editor input copy", edit: true},
		{name: "gRPC binary spooling"},
		{name: "gRPC JSON conversion", json: true},
		{name: "gRPC dry-run binary materialization", dryRun: true},
		{name: "gRPC dry-run JSON conversion", dryRun: true, json: true},
		{name: "gRPC dry-run streaming materialization", dryRun: true, json: true, clientStream: true},
	}
	for _, cancellation := range []string{"timeout", "caller"} {
		for _, tt := range tests {
			t.Run(cancellation+"/"+tt.name, func(t *testing.T) {
				reader, writer := io.Pipe()
				defer writer.Close()
				input := &preparationPipe{PipeReader: reader, started: make(chan struct{}), closed: make(chan struct{})}
				defer input.Close()
				r := &Request{
					Data: input, Discard: true, HTTP: core.HTTP1,
					PrinterHandle: core.NewHandle(core.ColorOff), Verbosity: core.VSilent,
					URL:    mustParseURL(server.URL + "/testpkg.TestService/Call"),
					DryRun: tt.dryRun,
					Edit:   tt.edit,
				}
				if tt.aws {
					r.AWSSigv4 = testAWSRequest().AWSSigv4
				} else if !tt.edit {
					r.GRPC = true
					r.ProtoDesc = descriptorPath
				}
				if tt.json {
					r.ContentType = "application/json"
				}
				if tt.clientStream {
					r.URL.Path = "/testpkg.TestService/Stream"
				}
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				if cancellation == "timeout" {
					r.Timeout = 100 * time.Millisecond
				}
				result := make(chan error, 1)
				go func() {
					_, err := fetch(ctx, r)
					result <- err
				}()
				select {
				case <-input.started:
				case err := <-result:
					t.Fatalf("fetch returned before reading the input: %v", err)
				case <-time.After(2 * time.Second):
					t.Fatal("preparation did not start reading the input")
				}
				callerCause := errors.New("caller canceled preparation")
				if cancellation == "caller" {
					cancel(callerCause)
				}
				select {
				case err := <-result:
					if cancellation == "caller" {
						if !errors.Is(err, callerCause) {
							t.Fatalf("fetch error = %v, want caller cancellation cause", err)
						}
					} else {
						var timeout core.TimeoutError
						if !errors.As(err, &timeout) || timeout.Duration != r.Timeout || timeout.Connection {
							t.Fatalf("fetch error = %v, want request timeout after %s", err, r.Timeout)
						}
					}
				case <-time.After(2 * time.Second):
					t.Fatal("cancellation did not unblock request preparation")
				}
				select {
				case <-input.closed:
				default:
					t.Fatal("canceled input was not closed")
				}
			})
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("sent %d network requests with incomplete preparation", got)
	}
}

func TestRetryUsesPreparationBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	r := &Request{
		Timeout: time.Second, Discard: true,
		URL: mustParseURL(server.URL), PrinterHandle: core.NewHandle(core.ColorOff),
	}
	c := newClient(r)
	defer c.Close()
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Model preparation consuming most of a request's budget. The configured
	// timeout must not give the network attempt a fresh second.
	budget, err := core.NewBudgetAt(time.Second, time.Now().Add(-950*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = retryableRequestWithBudget(context.Background(), r, c, req, budget)
	var timeout core.TimeoutError
	if !errors.As(err, &timeout) || timeout.Duration != time.Second {
		t.Fatalf("retry error = %v, want the original request timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("network attempt restarted the timeout: elapsed %s", elapsed)
	}
}

func TestRequestBudgetCoversProtoCompilation(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is required to build the compiler fixture")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	const program = `package main
import "time"
func main() { for { time.Sleep(time.Second) } }
`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "protoc")
	if os.PathSeparator == '\\' {
		helper += ".exe"
	}
	cmd := exec.CommandContext(t.Context(), goTool, "build", "-o", helper, source)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GO111MODULE=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build compiler fixture: %v\n%s", err, output)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, discovery := range []bool{false, true} {
		name := "call"
		if discovery {
			name = "discovery"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := &Request{
				GRPC: true, GRPCList: discovery, ProtoFiles: []string{"unused.proto"},
				Timeout: 100 * time.Millisecond, PrinterHandle: core.NewHandle(core.ColorOff),
				URL: mustParseURL("http://localhost/testpkg.TestService/Call"),
			}
			result := make(chan error, 1)
			go func() {
				var err error
				if discovery {
					_, err = discoverGRPC(ctx, r)
				} else {
					_, err = fetch(ctx, r)
				}
				result <- err
			}()
			select {
			case err := <-result:
				var timeout core.TimeoutError
				if !errors.As(err, &timeout) || timeout.Duration != r.Timeout {
					t.Fatalf("schema preparation error = %v, want request timeout", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("schema preparation ignored the request timeout")
			}
		})
	}
}

func TestEditorProcessHonorsCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(t.TempDir(), "editor-ready")
	t.Setenv("FETCH_TEST_EDITOR_READY", readyPath)
	t.Setenv("VISUAL", fmt.Sprintf("%q -test.run=^TestPreparationEditorHelper$ --", executable))
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- editRequestBody(req) }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		select {
		case err := <-result:
			t.Fatalf("editor exited before cancellation: %v", err)
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("editor helper did not start")
		}
	}
	cause := errors.New("cancel editor")
	cancel(cause)
	select {
	case err := <-result:
		if !errors.Is(err, cause) {
			t.Fatalf("editor error = %v, want cancellation cause", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("editor process did not stop on cancellation")
	}
}

func TestPreparationEditorHelper(t *testing.T) {
	path := os.Getenv("FETCH_TEST_EDITOR_READY")
	if path == "" {
		return
	}
	if err := os.WriteFile(path, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Second)
	}
}

type preparationPipe struct {
	*io.PipeReader
	started   chan struct{}
	once      sync.Once
	closed    chan struct{}
	closeOnce sync.Once
}

func (r *preparationPipe) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.PipeReader.Read(p)
}

func (r *preparationPipe) Close() error {
	r.closeOnce.Do(func() {
		_ = r.PipeReader.Close()
		close(r.closed)
	})
	return nil
}
