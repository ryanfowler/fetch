package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/cli"
	"github.com/ryanfowler/fetch/internal/config"
	"github.com/ryanfowler/fetch/internal/core"
)

func TestIgnoredInspectionFlags(t *testing.T) {
	app := inspectionFlagTestApp(t)

	common := []string{
		"--data/--json/--xml",
		"--form",
		"--multipart",
		"--grpc",
		"--grpc-describe",
		"--grpc-list",
		"--output",
		"--remote-name",
		"--remote-header-name",
		"--copy",
		"--method",
		"--header",
		"--query",
		"--edit",
		"--session",
		"--retry",
		"--range",
		"--timing",
		"--proxy",
		"--discard",
		"--unix",
	}

	if got := ignoredInspectionFlags(app, inspectionTLS); !slices.Equal(got, common) {
		t.Fatalf("ignoredInspectionFlags(inspectionTLS) = %v, want %v", got, common)
	}

	wantDNS := append(slices.Clone(common),
		"--inspect-tls",
		"--bearer",
		"--basic",
		"--digest",
		"--aws-sigv4",
		"--ca-cert",
		"--cert",
		"--key",
		"--tls",
		"--max-tls",
		"--insecure",
		"--format",
		"--dry-run",
	)
	if got := ignoredInspectionFlags(app, inspectionDNS); !slices.Equal(got, wantDNS) {
		t.Fatalf("ignoredInspectionFlags(inspectionDNS) = %v, want %v", got, wantDNS)
	}
}

func TestWarnIgnoredInspectionFlagsDoesNotAddBlankLine(t *testing.T) {
	p := core.TestPrinter(false)

	warnIgnoredInspectionFlags(p, inspectionDNS, []string{"--timing"})

	got := string(p.Bytes())
	want := "warning: --inspect-dns ignores: --timing\n"
	if got != want {
		t.Fatalf("warning output = %q, want %q", got, want)
	}
}

func inspectionFlagTestApp(t *testing.T) *cli.App {
	t.Helper()

	copyOutput := true
	insecure := true
	retry := 1
	session := "session-name"
	timing := true
	tlsMax := uint16(tls.VersionTLS13)
	tlsMin := uint16(tls.VersionTLS12)
	proxyURL, err := url.Parse("http://proxy.test")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	return &cli.App{
		AWSSigv4:         &aws.Config{},
		Basic:            &core.KeyVal[string]{Key: "user", Val: "pass"},
		Bearer:           "token",
		Data:             strings.NewReader("body"),
		Digest:           &core.KeyVal[string]{Key: "user", Val: "pass"},
		Discard:          true,
		DryRun:           true,
		Edit:             true,
		Form:             []core.KeyVal[string]{{Key: "field", Val: "value"}},
		GRPC:             true,
		GRPCDescribe:     "service.Method",
		GRPCList:         true,
		InspectTLS:       true,
		Method:           "POST",
		Multipart:        []core.KeyVal[string]{{Key: "file", Val: "path"}},
		Output:           "out.txt",
		Range:            []string{"0-10"},
		RemoteHeaderName: true,
		RemoteName:       true,
		UnixSocket:       "/tmp/fetch.sock",
		Cfg: config.Config{
			CACerts:     []*x509.Certificate{{}},
			CertPath:    "client.pem",
			Copy:        &copyOutput,
			Format:      core.FormatOn,
			Headers:     []core.KeyVal[string]{{Key: "X-Test", Val: "1"}},
			Insecure:    &insecure,
			KeyPath:     "client-key.pem",
			Proxy:       proxyURL,
			QueryParams: []core.KeyVal[string]{{Key: "q", Val: "1"}},
			Retry:       &retry,
			Session:     &session,
			Timing:      &timing,
			TLSMax:      &tlsMax,
			TLSMin:      &tlsMin,
		},
	}
}
