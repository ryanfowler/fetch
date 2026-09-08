package fetch

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
)

func TestSetWebTransportMethod(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		explicit bool
		warning  string
	}{
		{name: "default GET", method: http.MethodGet},
		{name: "body-inferred POST", method: http.MethodPost},
		{name: "explicit non-CONNECT", method: http.MethodPut, explicit: true, warning: "ignoring method PUT"},
		{name: "explicit CONNECT", method: http.MethodConnect, explicit: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(test.method, "https://example.com/path", nil)
			if err != nil {
				t.Fatal(err)
			}
			p := core.TestPrinter(false)

			setWebTransportMethod(req, test.explicit, p, false)

			if req.Method != http.MethodConnect {
				t.Fatalf("method = %q, want CONNECT", req.Method)
			}
			output := string(p.Bytes())
			if test.warning != "" && !strings.Contains(output, test.warning) {
				t.Fatalf("warning output = %q, want %q", output, test.warning)
			}
			if test.warning == "" && output != "" {
				t.Fatalf("unexpected warning output: %q", output)
			}
		})
	}
}

func TestSetWebTransportMethodUsesInferredBodyMethod(t *testing.T) {
	c := client.NewClient(client.ClientConfig{})
	defer c.Close()

	req, err := c.NewRequest(t.Context(), client.RequestConfig{
		Data:   strings.NewReader("payload"),
		URL:    mustParseURL("https://example.com/path"),
		Method: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("inferred method = %q, want POST", req.Method)
	}

	setWebTransportMethod(req, false, core.TestPrinter(false), false)
	if req.Method != http.MethodConnect {
		t.Fatalf("method = %q, want CONNECT", req.Method)
	}
}

func TestWebTransportAWSMethodSigningUsesCONNECT(t *testing.T) {
	cfg := aws.Config{
		AccessKey: "AKIDEXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region:    "us-east-1",
		Service:   "execute-api",
	}
	when := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

	req, err := http.NewRequest(http.MethodGet, "https://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	setWebTransportMethod(req, false, core.TestPrinter(false), false)
	if err := aws.Sign(req, cfg, when); err != nil {
		t.Fatal(err)
	}
	got := req.Header.Get("Authorization")

	connectReq, _ := http.NewRequest(http.MethodConnect, "https://example.com/path", nil)
	if err := aws.Sign(connectReq, cfg, when); err != nil {
		t.Fatal(err)
	}
	if got != connectReq.Header.Get("Authorization") {
		t.Fatalf("signature was not calculated for CONNECT: got %q, want %q", got, connectReq.Header.Get("Authorization"))
	}

	getReq, _ := http.NewRequest(http.MethodGet, "https://example.com/path", nil)
	if err := aws.Sign(getReq, cfg, when); err != nil {
		t.Fatal(err)
	}
	if got == getReq.Header.Get("Authorization") {
		t.Fatal("CONNECT and GET signatures are equal")
	}
}

func TestWebTransportDryRunMetadataUsesCONNECT(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	setWebTransportMethod(req, false, core.TestPrinter(false), false)

	p := core.TestPrinter(false)
	printRequestMetadataWithURL(p, req, core.HTTP3, core.VSilent, true)
	if got := string(p.Bytes()); !strings.Contains(got, "CONNECT /path HTTP/3.0") {
		t.Fatalf("dry-run metadata = %q, want CONNECT request line", got)
	}
	if strings.Contains(string(p.Bytes()), "GET /path") {
		t.Fatalf("dry-run metadata contains stale GET request line: %q", p.Bytes())
	}
}
