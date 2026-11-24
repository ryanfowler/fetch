package cli

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/aws"
)

func TestFromCurlAWSSigv4UsesUserAsKeys(t *testing.T) {
	// Environment credentials must not win over the keys from -u, and the
	// environment's session token belongs to the environment's key.
	t.Setenv("AWS_ACCESS_KEY_ID", "ENVKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	t.Setenv("AWS_SESSION_TOKEN", "envtoken")
	app, err := Parse([]string{"--from-curl", "curl --aws-sigv4 aws:amz:us-east-1:execute-api -u AKID:SECRET https://example.com"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if app.Basic != nil {
		t.Fatal("Basic auth is set, want none: -u holds the AWS keys")
	}
	if app.OptionWasExplicit("basic") {
		t.Fatal("basic is recorded as an explicit option")
	}
	if app.AWSSigv4 == nil {
		t.Fatal("AWSSigv4 is not set")
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aws.Sign(req, *app.AWSSigv4, time.Now()); err != nil {
		t.Fatal(err)
	}
	if auth := req.Header.Get("Authorization"); !strings.Contains(auth, "Credential=AKID/") {
		t.Fatalf("Authorization does not use the access key from -u: %q", auth)
	}
	if req.Header.Get("X-Amz-Security-Token") != "" {
		t.Fatal("the environment session token was sent with the keys from -u")
	}
}

func TestFromCurlAWSSigv4RejectsInvalidUser(t *testing.T) {
	for _, command := range []string{
		"curl --aws-sigv4 aws:amz:us-east-1:s3 -u AKID: https://example.com",
		"curl --aws-sigv4 aws:amz:us-east-1:s3 -u :SECRET https://example.com",
		"curl --aws-sigv4 aws:amz:us-east-1:s3 -u AKID https://example.com",
	} {
		_, err := Parse([]string{"--from-curl", command})
		if err == nil || !strings.Contains(err.Error(), "ACCESS_KEY:SECRET_KEY") {
			t.Errorf("%s: error = %v, want an AWS key format error", command, err)
		}
	}
	_, err := Parse([]string{"--from-curl", "curl --aws-sigv4 aws:amz:us-east-1:s3 --digest -u AKID:SECRET https://example.com"})
	if err == nil || !strings.Contains(err.Error(), "--digest") {
		t.Errorf("--aws-sigv4 with --digest: error = %v, want a rejection", err)
	}
}

func TestFromCurlUserWithoutAWSSigv4(t *testing.T) {
	app, err := Parse([]string{"--from-curl", "curl -u user:pass https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if app.Basic == nil || app.Basic.Key != "user" {
		t.Fatal("-u without --aws-sigv4 did not set Basic auth")
	}
	app, err = Parse([]string{"--from-curl", "curl --digest -u user:pass https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if app.Digest == nil || app.Basic != nil {
		t.Fatal("--digest -u did not set Digest auth only")
	}
	// Without -u, the keys come from the environment at signing time.
	app, err = Parse([]string{"--from-curl", "curl --aws-sigv4 aws:amz:us-east-1:s3 https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if app.AWSSigv4.AccessKey != "" {
		t.Fatal("AccessKey is set without -u")
	}
}
