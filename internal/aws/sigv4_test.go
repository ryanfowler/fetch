package aws

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSign(t *testing.T) {
	t.Setenv("AWS_SESSION_TOKEN", "")
	tests := []struct {
		name      string
		region    string
		service   string
		accessID  string
		secretKey string
		request   func() *http.Request
		now       time.Time
		expErr    string
		expAuth   string
	}{
		{
			name:      "get object",
			region:    "us-east-1",
			service:   "s3",
			accessID:  "AKIAIOSFODNN7EXAMPLE",
			secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
				req.Header.Set("Range", "bytes=0-9")
				return req
			},
			now:     time.Date(2013, 05, 24, 0, 0, 0, 0, time.UTC),
			expAuth: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		},
		{
			name:      "put object",
			region:    "us-east-1",
			service:   "s3",
			accessID:  "AKIAIOSFODNN7EXAMPLE",
			secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			request: func() *http.Request {
				body := "Welcome to Amazon S3."
				req, _ := http.NewRequest("PUT", "https://examplebucket.s3.amazonaws.com/test$file.text", strings.NewReader(body))
				req.Header.Set("Date", "Fri, 24 May 2013 00:00:00 GMT")
				req.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
				return req
			},
			now:     time.Date(2013, 05, 24, 0, 0, 0, 0, time.UTC),
			expAuth: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		},
		{
			name:      "get bucket lifecycle",
			region:    "us-east-1",
			service:   "s3",
			accessID:  "AKIAIOSFODNN7EXAMPLE",
			secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/?lifecycle", nil)
				return req
			},
			now:     time.Date(2013, 05, 24, 0, 0, 0, 0, time.UTC),
			expAuth: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		},
		{
			name:      "list objects",
			region:    "us-east-1",
			service:   "s3",
			accessID:  "AKIAIOSFODNN7EXAMPLE",
			secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
				return req
			},
			now:     time.Date(2013, 05, 24, 0, 0, 0, 0, time.UTC),
			expAuth: "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := test.request()
			cfg := Config{
				Region:    test.region,
				Service:   test.service,
				AccessKey: test.accessID,
				SecretKey: test.secretKey,
			}
			err := Sign(req, cfg, test.now)
			if err != nil {
				if test.expErr == "" {
					t.Fatalf("unexpected error: %s", err.Error())
				}
				if !strings.Contains(err.Error(), test.expErr) {
					t.Fatalf("unexpected error: %s", err.Error())
				}
				return
			}
			if test.expErr != "" {
				t.Fatal("error did not occur")
			}

			auth := req.Header.Get("Authorization")
			if auth != test.expAuth {
				t.Fatalf("unexpected auth header: %s", auth)
			}
		})
	}
}

func TestSignLoadsMissingCredentialsFromEnv(t *testing.T) {
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	cfg := Config{
		Region:  "us-east-1",
		Service: "s3",
	}
	err := Sign(req, cfg, time.Date(2013, 05, 24, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request") {
		t.Fatalf("Authorization = %q, want env access key credential", auth)
	}
}

func TestSignReportsMissingEnvCredentials(t *testing.T) {
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	err := Sign(req, Config{Region: "us-east-1", Service: "s3"}, time.Date(2013, 05, 24, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("Sign() error = nil, want missing env error")
	}
	if !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") {
		t.Fatalf("Sign() error = %q, want AWS_ACCESS_KEY_ID", err.Error())
	}
}

func TestSignIncludesSessionTokenFromEnvironment(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "session-token")

	req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err := Sign(req, Config{Region: "us-east-1", Service: "s3"}, time.Date(2013, 05, 24, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "session-token" {
		t.Fatalf("security token = %q, want session-token", got)
	}
	if got := req.Header.Get("Authorization"); !strings.Contains(got, "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token") {
		t.Fatalf("Authorization = %q, want signed security token", got)
	}
}

func TestCanonicalQueryUsesEncodedSortOrderAndLiteralPlus(t *testing.T) {
	u, err := url.Parse("https://example.com/?z=last&%C3%A9=first&space=a+b&space=a%20b&empty=&bare&dup=b&dup=a")
	if err != nil {
		t.Fatal(err)
	}
	want := "%C3%A9=first&bare=&dup=a&dup=b&empty=&space=a%20b&space=a%2Bb&z=last"
	if got := canonicalQuery(u); got != want {
		t.Fatalf("canonical query = %q, want %q", got, want)
	}
}

func TestGetSignedHeadersCanonicalizesHeaderValues(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header["X-Foo"] = []string{"  a  ", "  b  "}
	req.Header.Set("X-Bar", "  a\t \n b  ")

	headers := getSignedHeaders(req)

	tests := map[string]string{
		"x-bar": "a b",
		"x-foo": "a,b",
	}
	for key, want := range tests {
		t.Run(key, func(t *testing.T) {
			for _, header := range headers {
				if header.Key == key {
					if header.Val != want {
						t.Fatalf("unexpected value: got %q, want %q", header.Val, want)
					}
					return
				}
			}
			t.Fatalf("signed header %q not found", key)
		})
	}
}

func TestGetSignedHeadersMergesCaseVariantKeysDeterministically(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header["x-foo"] = []string{"b"}
	req.Header["X-Foo"] = []string{"a"}

	for i := 0; i < 20; i++ {
		var got string
		for _, header := range getSignedHeaders(req) {
			if header.Key == "x-foo" {
				got = header.Val
				break
			}
		}
		if got != "a,b" {
			t.Fatalf("merged x-foo = %q, want a,b", got)
		}
	}
}

func TestBuildCanonicalRequestEncodesPathForService(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		service string
		want    string
	}{
		{
			name:    "s3 escaped slash",
			url:     "https://example.com/a%2Fb",
			service: "s3",
			want:    "/a%2Fb",
		},
		{
			name:    "s3 escaped space",
			url:     "https://example.com/space%20here",
			service: "s3",
			want:    "/space%20here",
		},
		{
			name:    "s3 non-ascii segment",
			url:     "https://example.com/café/日本",
			service: "s3",
			want:    "/caf%C3%A9/%E6%97%A5%E6%9C%AC",
		},
		{
			name:    "non-s3 escaped slash",
			url:     "https://example.com/a%2Fb",
			service: "execute-api",
			want:    "/a%252Fb",
		},
		{
			name:    "non-s3 escaped space",
			url:     "https://example.com/space%20here",
			service: "execute-api",
			want:    "/space%2520here",
		},
		{
			name:    "non-s3 non-ascii segment",
			url:     "https://example.com/café/日本",
			service: "execute-api",
			want:    "/caf%25C3%25A9/%25E6%2597%25A5%25E6%259C%25AC",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", test.url, nil)

			canonicalRequest := string(buildCanonicalRequest(req, nil, emptySha256, test.service))
			lines := strings.SplitN(canonicalRequest, "\n", 3)
			if lines[1] != test.want {
				t.Fatalf("unexpected canonical path: got %q, want %q", lines[1], test.want)
			}
		})
	}
}

func TestGetSignedHeadersUsesRequestHost(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://127.0.0.1", nil)
	req.Host = "vhost.example"

	headers := getSignedHeaders(req)

	for _, header := range headers {
		if header.Key == "host" {
			if header.Val != "vhost.example" {
				t.Fatalf("unexpected host: got %q, want %q", header.Val, "vhost.example")
			}
			return
		}
	}
	t.Fatal("signed host header not found")
}

func TestGetSignedHeadersStripsSchemeDefaultPort(t *testing.T) {
	tests := []struct {
		name string
		url  string
		host string
		want string
	}{
		{name: "https", url: "https://example.com:443", want: "example.com"},
		{name: "http", url: "http://example.com:80", want: "example.com"},
		{name: "non-default port", url: "https://example.com:8443", want: "example.com:8443"},
		{name: "ipv6 https", url: "https://[2001:db8::1]:443", want: "[2001:db8::1]"},
		{name: "ipv6 non-default port", url: "https://[2001:db8::1]:8443", want: "[2001:db8::1]:8443"},
		{name: "request host", url: "https://127.0.0.1", host: "vhost.example:443", want: "vhost.example"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", test.url, nil)
			req.Host = test.host

			for _, header := range getSignedHeaders(req) {
				if header.Key == "host" {
					if header.Val != test.want {
						t.Fatalf("host = %q, want %q", header.Val, test.want)
					}
					return
				}
			}
			t.Fatal("signed host header not found")
		})
	}
}
