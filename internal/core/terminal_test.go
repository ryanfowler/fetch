package core

import (
	"errors"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

func TestTerminalSafeText(t *testing.T) {
	input := "ok\x1b[2J\x00\x7f\x80\u0085\tline\ninvalid\xff"
	got := TerminalSafeText(input)
	want := "ok\\x1b[2J\\x00\\x7f\\x80\\x85\tline\ninvalid\\xff"
	if got != want {
		t.Fatalf("TerminalSafeText() = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, "\x00\x1b\x7f") {
		t.Fatalf("terminal control byte survived: %q", got)
	}
}

func TestTerminalSafeTextCommonCaseDoesNotAllocate(t *testing.T) {
	input := "ordinary diagnostic text with UTF-8: café\n"
	allocs := testing.AllocsPerRun(100, func() {
		if got := TerminalSafeText(input); got != input {
			t.Fatalf("TerminalSafeText() changed safe input to %q", got)
		}
	})
	if allocs != 0 {
		t.Fatalf("TerminalSafeText() allocated %v times for safe input", allocs)
	}
}

func TestRedactHeaderValue(t *testing.T) {
	for _, name := range []string{"Authorization", "proxy-authorization", "Cookie", "Set-Cookie", "X-Amz-Security-Token"} {
		if got := RedactHeaderValue(name, "secret"); got != "[REDACTED]" {
			t.Errorf("RedactHeaderValue(%q) = %q", name, got)
		}
	}
	if got := RedactHeaderValue("X-Trace", "ok\x1b[2J"); got != `ok\x1b[2J` {
		t.Errorf("RedactHeaderValue() = %q", got)
	}
}

func TestRedactedURL(t *testing.T) {
	u, err := url.Parse("https://user:secret@example.test/path")
	if err != nil {
		t.Fatal(err)
	}
	if got := RedactedURL(u); got != "https://example.test/path" {
		t.Fatalf("RedactedURL() = %q", got)
	}
}

func TestIsBrokenPipe(t *testing.T) {
	if !IsBrokenPipe(syscall.EPIPE) {
		t.Fatal("syscall.EPIPE was not recognized")
	}
	if !IsBrokenPipe(errors.New("write failed: broken pipe")) {
		t.Fatal("broken pipe text was not recognized")
	}
	if !IsBrokenPipe(errors.New("write |1: The pipe has been ended.")) {
		t.Fatal("Windows broken pipe text was not recognized")
	}
	if IsBrokenPipe(errors.New("other output error")) {
		t.Fatal("unrelated error was recognized as broken pipe")
	}
}

func TestWarningWriterHonorsSilentAndNormalizesLayout(t *testing.T) {
	p := TestPrinter(false)
	w := NewWarningWriter(p, false)
	if err := w.Write("remote text\x1b[2J\n\n"); err != nil {
		t.Fatal(err)
	}
	if got, want := string(p.Bytes()), "warning: remote text\\x1b[2J\n"; got != want {
		t.Fatalf("warning output = %q, want %q", got, want)
	}

	p = TestPrinter(false)
	if err := NewWarningWriter(p, true).Write("hidden"); err != nil {
		t.Fatal(err)
	}
	if len(p.Bytes()) != 0 {
		t.Fatalf("silent warning wrote %q", p.Bytes())
	}
}
