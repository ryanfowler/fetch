package parity

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCompareIgnoresHeaderOrderButPreservesDuplicates(t *testing.T) {
	goResult := Result{
		ExitCode: 0,
		Stderr:   []byte("> GET / HTTP/1.1\n> z-last: value\n> x-duplicate: first\n> x-duplicate: second\n> a-first: value\n"),
	}
	rustResult := Result{
		ExitCode: 0,
		Stderr:   []byte("> GET / HTTP/1.1\n> a-first: value\n> x-duplicate: first\n> x-duplicate: second\n> z-last: value\n"),
	}

	if err := CompareResults(Case{Name: "header-order"}, goResult, rustResult, DefaultOptions()); err != nil {
		t.Fatalf("header order should not affect parity: %v", err)
	}

	rustResult.Stderr = []byte("> GET / HTTP/1.1\n> a-first: value\n> x-duplicate: first\n> z-last: value\n")
	err := CompareResults(Case{Name: "duplicate-header"}, goResult, rustResult, DefaultOptions())
	if err == nil || !strings.Contains(err.Error(), "stderr") {
		t.Fatalf("missing duplicate header should be reported as stderr mismatch, got %v", err)
	}

	goResult.Stderr = []byte("< HTTP/1.1 200 OK\n< x-parity-response: first,second\n")
	rustResult.Stderr = []byte("< HTTP/1.1 200 OK\n< x-parity-response: first\n< x-parity-response: second\n")
	if err := CompareResults(Case{Name: "comma-joined-duplicate-header"}, goResult, rustResult, DefaultOptions()); err != nil {
		t.Fatalf("comma-joined and repeated header values should compare equally: %v", err)
	}
	if err := CompareResults(Case{Name: "yaml-order"}, Result{ExitCode: 0, Stdout: []byte("z: value\na: value\n")}, Result{ExitCode: 0, Stdout: []byte("a: value\nz: value\n")}, DefaultOptions()); err == nil {
		t.Fatal("unprefixed YAML-like output must not be treated as HTTP headers")
	}
}

func TestNormalizeDocumentedNondeterminism(t *testing.T) {
	result := Result{
		ExitCode:   0,
		WorkingDir: "/tmp/fetch-parity-go",
		Stdout:     []byte("duration: 12.5ms dns transaction id=0xabc URL=http://127.0.0.1:43123/out at 2026-08-20T12:00:00Z /tmp/fetch-parity-go/file\n"),
	}
	value := normalizeText(string(result.Stdout), result.WorkingDir, DefaultOptions())
	for _, want := range []string{"<timing>", "<dns-id>", "<port>", "<date>", "<workdir>"} {
		if !strings.Contains(value, want) {
			t.Errorf("normalized output missing %q: %s", want, value)
		}
	}
	if value := normalizeText("id=0xabc", "", DefaultOptions()); strings.Contains(value, "<dns-id>") {
		t.Fatalf("generic IDs must not be normalized: %s", value)
	}
	timing := normalizeText("DNS: host (12 ms)\nTCP: 127.0.0.1:443 (13.0 ms)\nTLS: cipher (14 ms)\nTTFB: 15 ms\n", "", DefaultOptions())
	if strings.Contains(timing, "12 ms") || strings.Contains(timing, "13.0 ms") || strings.Contains(timing, "14 ms") || strings.Contains(timing, "15 ms") {
		t.Fatalf("CLI timing values must be normalized: %s", timing)
	}
	dates := normalizeText("Thu, 05 Feb 2026 00:33:27 GMT and 2026-02-05", "", DefaultOptions())
	if strings.Contains(dates, "Feb 2026") || strings.Contains(dates, "2026-02-05") {
		t.Fatalf("HTTP and date-only values must be normalized: %s", dates)
	}
}

func TestCompareNormalizesTextFiles(t *testing.T) {
	goResult := Result{
		ExitCode:   0,
		WorkingDir: "/tmp/fetch-parity-go",
		Files: map[string]File{
			"metadata.txt": {
				Present: true,
				Data:    []byte("created=2026-08-20T12:00:00Z /tmp/fetch-parity-go/output\n"),
			},
		},
	}
	rustResult := Result{
		ExitCode:   0,
		WorkingDir: "/tmp/fetch-parity-rust",
		Files: map[string]File{
			"metadata.txt": {
				Present: true,
				Data:    []byte("created=2026-08-21T12:00:00Z /tmp/fetch-parity-rust/output\n"),
			},
		},
	}
	if err := CompareResults(Case{Name: "text-file-normalization"}, goResult, rustResult, DefaultOptions()); err != nil {
		t.Fatalf("text file nondeterminism should be normalized: %v", err)
	}
}

func TestRunCapturesExitOutputAndFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("process fixture is not useful in short mode")
	}
	caseDef := Case{
		Name:         "helper-process-fixture",
		Timeout:      5 * time.Second,
		Args:         []string{"-test.run=TestParityHelperProcess"},
		Env:          []string{"FETCH_PARITY_HELPER=1"},
		Stdin:        []byte("fixture"),
		CaptureFiles: []string{"result.txt"},
	}
	result, err := NewRunner().Run(context.Background(), os.Args[0], caseDef)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Cleanup()
	if result.ExitCode != 0 || string(result.Stdout) != "out" || string(result.Stderr) != "err" {
		t.Fatalf("unexpected process result: %#v", result)
	}
	file := result.Files["result.txt"]
	if !file.Present || string(file.Data) != "fixture" {
		t.Fatalf("unexpected captured file: %#v", file)
	}
}

func TestParityHelperProcess(t *testing.T) {
	if os.Getenv("FETCH_PARITY_HELPER") != "1" {
		return
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile("result.txt", data, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print("out")
	fmt.Fprint(os.Stderr, "err")
	os.Exit(0)
}
