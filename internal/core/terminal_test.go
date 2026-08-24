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

func TestPrinterWriteUntrustedEscapesTerminalControls(t *testing.T) {
	p := TestPrinter(false)
	if _, err := p.WriteStringUntrusted("title\x1b]0;pwned\x07\n"); err != nil {
		t.Fatal(err)
	}
	if got, want := string(p.Bytes()), `title\x1b]0;pwned\x07
`; got != want {
		t.Fatalf("untrusted output = %q, want %q", got, want)
	}

	p = TestPrinter(false)
	if _, err := p.WriteUntrusted([]byte("bad\xff")); err != nil {
		t.Fatal(err)
	}
	if got, want := string(p.Bytes()), `bad\xff`; got != want {
		t.Fatalf("untrusted bytes = %q, want %q", got, want)
	}
}

func TestPrinterHyperlink(t *testing.T) {
	p := TestTerminalPrinter(false)
	if !p.StartHyperlink("https://example.com/docs") {
		t.Fatal("StartHyperlink() = false, want true")
	}
	_, _ = p.WriteString("docs")
	p.EndHyperlink()

	want := "\x1b]8;;https://example.com/docs\x1b\\docs\x1b]8;;\x1b\\"
	if got := string(p.Bytes()); got != want {
		t.Fatalf("hyperlink output = %q, want %q", got, want)
	}
}

func TestPrinterHyperlinkRejectsTerminalControls(t *testing.T) {
	for _, target := range []string{"", "https://example.com\nnext", "https://example.com\x1b\\"} {
		p := TestTerminalPrinter(false)
		if p.StartHyperlink(target) {
			t.Errorf("StartHyperlink(%q) = true, want false", target)
		}
		if len(p.Bytes()) != 0 {
			t.Errorf("StartHyperlink(%q) wrote %q", target, p.Bytes())
		}
	}
}

func TestPrinterHyperlinkRejectsUnsafeSchemes(t *testing.T) {
	for _, target := range []string{"javascript:alert(1)", "data:text/html,hello", "file:///etc/passwd"} {
		p := TestTerminalPrinter(false)
		if p.StartHyperlink(target) {
			t.Errorf("StartHyperlink(%q) = true, want false", target)
		}
	}
	for _, target := range []string{"https://example.com", "mailto:user@example.com"} {
		p := TestTerminalPrinter(false)
		if !p.StartHyperlink(target) {
			t.Errorf("StartHyperlink(%q) = false, want true", target)
		}
	}
}

func TestPrinterNonTerminalDoesNotEmitHyperlink(t *testing.T) {
	p := TestPrinter(false)
	if p.StartHyperlink("https://example.com") {
		t.Fatal("StartHyperlink() = true for non-terminal printer")
	}
	if len(p.Bytes()) != 0 {
		t.Fatalf("non-terminal hyperlink output = %q", p.Bytes())
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

func TestTerminalSafeBytesMatchesTerminalSafeText(t *testing.T) {
	inputs := []string{
		"ordinary diagnostic text with UTF-8: café\n",
		"controls\x00\x01\x1b[2J\x7f\x80\u0085\tline",
		"invalid UTF-8: \xff\xc3",
		"unicode control: \u009f",
	}

	for _, input := range inputs {
		src := []byte(input)
		want := TerminalSafeText(input)
		if got := string(TerminalSafeBytes(src)); got != want {
			t.Errorf("TerminalSafeBytes(%q) = %q, want %q", input, got, want)
		}

		dst := make([]byte, len("prefix:"), len("prefix:")+len(src)+16)
		copy(dst, "prefix:")
		got := AppendTerminalSafeBytes(dst, src)
		if want := "prefix:" + TerminalSafeText(input); string(got) != want {
			t.Errorf("AppendTerminalSafeBytes(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestTerminalSafeBytesSafeInputReturnsSource(t *testing.T) {
	src := []byte("safe UTF-8: café\n")
	got := TerminalSafeBytes(src)
	if len(got) == 0 || &got[0] != &src[0] {
		t.Fatal("TerminalSafeBytes copied safe input")
	}
}

func BenchmarkAppendTerminalSafeBytes(b *testing.B) {
	cases := map[string][]byte{
		"SafeText": []byte(strings.Repeat("ordinary text with UTF-8: café\n", 128)),
		"Controls": []byte(strings.Repeat("line\x1b[2J\x07\x00\n", 128)),
	}
	for name, src := range cases {
		b.Run(name, func(b *testing.B) {
			dst := make([]byte, 0, len(src)*4)
			b.SetBytes(int64(len(src)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				dst = AppendTerminalSafeBytes(dst[:0], src)
			}
			_ = dst
		})
	}
}

func TestRedactHeaderValue(t *testing.T) {
	for _, name := range []string{
		"Authorization", "proxy-authorization", "Cookie", "Set-Cookie", "X-Amz-Security-Token",
		"X-API-Key", "X-AuthToken", "X-ClientSecret", "X-Request-Signature", "X-PrivateKey", "X-Session-ID",
		"x-aPiKey", "X-rEqUeStSiGnAtUrE", "x-cLiEnTiD", "x-accesskey", "X-AccessKey", "x-aCcEsSkEy",
	} {
		if got := RedactHeaderValue(name, "secret"); got != "[REDACTED]" {
			t.Errorf("RedactHeaderValue(%q) = %q", name, got)
		}
	}
	if got := RedactHeaderValue("X-KeyboardLayout", "keyboard-layout"); got != "keyboard-layout" {
		t.Errorf("RedactHeaderValue(X-KeyboardLayout) = %q", got)
	}
	if got := RedactHeaderValue("X-Trace", "ok\x1b[2J"); got != `ok\x1b[2J` {
		t.Errorf("RedactHeaderValue() = %q", got)
	}
}

func TestWriteErrorMsgRedactsTransportURL(t *testing.T) {
	err := &url.Error{
		Op:  "Get",
		URL: "https://example.test/request?access_token=transport-query-secret&safe=ok",
		Err: errors.New("connection refused"),
	}
	p := TestPrinter(false)
	WriteErrorMsgNoFlush(p, err)

	got := string(p.Bytes())
	if strings.Contains(got, "transport-query-secret") {
		t.Fatalf("transport error leaked query secret: %q", got)
	}
	if want := "https://example.test/request?access_token=%5BREDACTED%5D&safe=ok"; !strings.Contains(got, want) {
		t.Fatalf("transport error = %q, want redacted URL %q", got, want)
	}
}

func TestWriteErrorMsgRedactsMalformedTransportURLUserinfo(t *testing.T) {
	err := &url.Error{
		Op:  "Get",
		URL: "https://transport-user:transport-password@example.test/request/%zz?access_token=transport-query-secret&safe=ok",
		Err: errors.New("connection refused"),
	}
	p := TestPrinter(false)
	WriteErrorMsgNoFlush(p, err)

	got := string(p.Bytes())
	for _, secret := range []string{"transport-user", "transport-password", "transport-query-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("malformed transport error leaked %q: %q", secret, got)
		}
	}
	want := "https://example.test/request/%zz?access_token=%5BREDACTED%5D&safe=ok"
	if !strings.Contains(got, want) {
		t.Fatalf("malformed transport error = %q, want redacted URL %q", got, want)
	}
}

func TestWriteErrorMsgRedactsStructurallyMalformedTransportURLUserinfo(t *testing.T) {
	err := &url.Error{
		Op:  "Get",
		URL: "http:/transport-user:transport-password@example.test/request?access_token=transport-query-secret&safe=ok",
		Err: errors.New("connection refused"),
	}
	p := TestPrinter(false)
	WriteErrorMsgNoFlush(p, err)

	got := string(p.Bytes())
	for _, secret := range []string{"transport-user", "transport-password", "transport-query-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("structurally malformed transport error leaked %q: %q", secret, got)
		}
	}
	want := "http:/example.test/request?access_token=%5BREDACTED%5D&safe=ok"
	if !strings.Contains(got, want) {
		t.Fatalf("structurally malformed transport error = %q, want redacted URL %q", got, want)
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

func TestRedactedURLRedactsStructurallyMalformedAuthority(t *testing.T) {
	u, err := url.Parse("http:/proxy-user:proxy-password@example.test?access_token=proxy-query-secret&safe=ok")
	if err != nil {
		t.Fatal(err)
	}

	got := RedactedURL(u)
	for _, secret := range []string{"proxy-user", "proxy-password", "proxy-query-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("RedactedURL() leaked %q: %q", secret, got)
		}
	}
	if want := "http:/example.test?access_token=%5BREDACTED%5D&safe=ok"; got != want {
		t.Fatalf("RedactedURL() = %q, want %q", got, want)
	}
}

func TestRedactedURLRedactsSensitiveQueryValues(t *testing.T) {
	u, err := url.Parse("https://example.test/path?safe=one&API_KEY=api-query-secret&access_token=access-query-token-secret&clientSecret=client-query-secret&x%2Dsignature=signature-query-secret&safe=two")
	if err != nil {
		t.Fatal(err)
	}

	got := RedactedURL(u)
	for _, value := range []string{"api-query-secret", "access-query-token-secret", "client-query-secret", "signature-query-secret"} {
		if strings.Contains(got, value) {
			t.Errorf("RedactedURL() leaked %q: %q", value, got)
		}
	}
	want := "https://example.test/path?safe=one&API_KEY=%5BREDACTED%5D&access_token=%5BREDACTED%5D&clientSecret=%5BREDACTED%5D&x%2Dsignature=%5BREDACTED%5D&safe=two"
	if got != want {
		t.Fatalf("RedactedURL() = %q, want %q", got, want)
	}
}

func TestRedactHeaderValueRedactsLocationURL(t *testing.T) {
	got := RedactHeaderValue("Location", "/next?password=secret&safe=ok")
	if strings.Contains(got, "secret") {
		t.Fatalf("Location redaction leaked secret: %q", got)
	}
	if want := "/next?password=%5BREDACTED%5D&safe=ok"; got != want {
		t.Fatalf("Location redaction = %q, want %q", got, want)
	}
}

func TestRedactHeaderValueRedactsStructurallyMalformedLocationURL(t *testing.T) {
	got := RedactHeaderValue("Location", "http:/location-user:location-password@example.test/next?access_token=location-query-secret&safe=ok")
	for _, secret := range []string{"location-user", "location-password", "location-query-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("structurally malformed Location leaked %q: %q", secret, got)
		}
	}
	if want := "http:/example.test/next?access_token=%5BREDACTED%5D&safe=ok"; got != want {
		t.Fatalf("structurally malformed Location = %q, want %q", got, want)
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
