package curl

import (
	"reflect"
	"testing"
)

func TestTokenize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "simple words",
			input: "curl https://example.com",
			want:  []string{"curl", "https://example.com"},
		},
		{
			name:  "single-quoted string",
			input: `curl 'https://example.com'`,
			want:  []string{"curl", "https://example.com"},
		},
		{
			name:  "double-quoted string",
			input: `curl "https://example.com"`,
			want:  []string{"curl", "https://example.com"},
		},
		{
			name:  "escaped characters",
			input: `curl https://example.com/path\ with\ spaces`,
			want:  []string{"curl", "https://example.com/path with spaces"},
		},
		{
			name:  "line continuation",
			input: "curl \\\nhttps://example.com",
			want:  []string{"curl", "https://example.com"},
		},
		{
			name:    "unterminated single quote",
			input:   "curl 'https://example.com",
			wantErr: true,
		},
		{
			name:    "unterminated double quote",
			input:   `curl "https://example.com`,
			wantErr: true,
		},
		{
			name:  "mixed quoting",
			input: `curl -H 'Content-Type: application/json' -d "hello world"`,
			want:  []string{"curl", "-H", "Content-Type: application/json", "-d", "hello world"},
		},
		{
			name:  "double quote escapes",
			input: `curl -d "say \"hello\""`,
			want:  []string{"curl", "-d", `say "hello"`},
		},
		{
			name:  "single quote preserves backslash",
			input: `curl -d 'hello\nworld'`,
			want:  []string{"curl", "-d", `hello\nworld`},
		},
		{
			name:  "tabs and extra whitespace",
			input: "curl \t  https://example.com  ",
			want:  []string{"curl", "https://example.com"},
		},
		{
			name:  "multiple line continuations",
			input: "curl \\\n  -X POST \\\n  https://example.com",
			want:  []string{"curl", "-X", "POST", "https://example.com"},
		},
		{
			name:  "empty single quotes produce token",
			input: "curl ''",
			want:  []string{"curl", ""},
		},
		{
			name:  "empty double quotes produce token",
			input: `curl ""`,
			want:  []string{"curl", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenize(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("tokenize() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("tokenize() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSimple(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		check   func(*testing.T, *Result)
		wantErr bool
	}{
		{
			name:  "simple GET",
			input: "curl https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "URL", r.URL, "https://example.com")
				assertEqual(t, "Method", r.Method, "")
			},
		},
		{
			name:  "without curl prefix",
			input: "https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "URL", r.URL, "https://example.com")
			},
		},
		{
			name:  "explicit GET method",
			input: "curl -X GET https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Method", r.Method, "GET")
				assertEqual(t, "URL", r.URL, "https://example.com")
			},
		},
		{
			name:  "POST with data",
			input: `curl -X POST -d "key=value" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Method", r.Method, "POST")
				assertDataValues(t, "DataValues", r.DataValues, []DataValue{{Value: "key=value"}})
			},
		},
		{
			name:  "inferred POST with data",
			input: `curl -d "data" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Method", r.Method, "POST")
			},
		},
		{
			name:  "headers",
			input: `curl -H "Content-Type: application/json" -H "Accept: text/plain" https://example.com`,
			check: func(t *testing.T, r *Result) {
				if len(r.Headers) != 2 {
					t.Fatalf("expected 2 headers, got %d", len(r.Headers))
				}
				assertEqual(t, "Headers[0].Name", r.Headers[0].Name, "Content-Type")
				assertEqual(t, "Headers[0].Value", r.Headers[0].Value, "application/json")
				assertEqual(t, "Headers[1].Name", r.Headers[1].Name, "Accept")
				assertEqual(t, "Headers[1].Value", r.Headers[1].Value, "text/plain")
			},
		},
		{
			name:  "multiple -d concatenation",
			input: `curl -d "a=1" -d "b=2" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertDataValues(t, "DataValues", r.DataValues, []DataValue{{Value: "a=1"}, {Value: "b=2"}})
			},
		},
		{
			name:  "data-raw",
			input: `curl --data-raw "@not-a-file" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertDataValues(t, "DataValues", r.DataValues, []DataValue{{Value: "@not-a-file", IsRaw: true}})
			},
		},
		{
			name:  "json flag",
			input: `curl --json '{"key":"value"}' https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertDataValues(t, "DataValues", r.DataValues, []DataValue{{Value: `{"key":"value"}`}})
				assertTrue(t, "HasContentType", r.HasContentType)
				assertTrue(t, "HasAccept", r.HasAccept)
				// Check Content-Type and Accept headers were added.
				foundCT := false
				foundAccept := false
				for _, h := range r.Headers {
					if h.Name == "Content-Type" && h.Value == "application/json" {
						foundCT = true
					}
					if h.Name == "Accept" && h.Value == "application/json" {
						foundAccept = true
					}
				}
				if !foundCT {
					t.Fatal("expected Content-Type: application/json header")
				}
				if !foundAccept {
					t.Fatal("expected Accept: application/json header")
				}
			},
		},
		{
			name:  "multipart form",
			input: `curl -F "name=value" -F "file=@path.txt" https://example.com`,
			check: func(t *testing.T, r *Result) {
				if len(r.FormFields) != 2 {
					t.Fatalf("expected 2 form fields, got %d", len(r.FormFields))
				}
				assertEqual(t, "FormFields[0].Name", r.FormFields[0].Name, "name")
				assertEqual(t, "FormFields[0].Value", r.FormFields[0].Value, "value")
				assertEqual(t, "FormFields[1].Name", r.FormFields[1].Name, "file")
				assertEqual(t, "FormFields[1].Value", r.FormFields[1].Value, "@path.txt")
			},
		},
		{
			name:  "HEAD request",
			input: "curl -I https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Method", r.Method, "HEAD")
			},
		},
		{
			name:  "GET flag with data",
			input: `curl -G -d "q=search" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Method", r.Method, "GET")
				assertEqual(t, "URL", r.URL, "https://example.com?q=search")
				if len(r.DataValues) != 0 {
					t.Fatalf("expected DataValues to be cleared, got %v", r.DataValues)
				}
			},
		},
		{
			name:  "GET flag with data and existing query",
			input: `curl -G -d "b=2" "https://example.com?a=1"`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "URL", r.URL, "https://example.com?a=1&b=2")
			},
		},
		{
			name:  "upload file",
			input: `curl -T file.txt https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "UploadFile", r.UploadFile, "file.txt")
				assertEqual(t, "Method", r.Method, "PUT")
			},
		},
		{
			name:  "explicit method overrides upload file default",
			input: `curl -X POST -T file.txt https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Method", r.Method, "POST")
				assertEqual(t, "UploadFile", r.UploadFile, "file.txt")
			},
		},
		{
			name:  "data-urlencode",
			input: `curl --data-urlencode "key=hello world" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertDataValues(t, "DataValues", r.DataValues, []DataValue{{Value: "key=hello+world"}})
			},
		},
		{
			name:  "data-urlencode bare content",
			input: `curl --data-urlencode "hello world" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertDataValues(t, "DataValues", r.DataValues, []DataValue{{Value: "hello+world"}})
			},
		},
		{
			name:  "data-urlencode @filename",
			input: `curl --data-urlencode "@myfile.txt" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertDataValues(t, "DataValues", r.DataValues, []DataValue{{Value: "@myfile.txt", IsURLEncode: true}})
			},
		},
		{
			name:  "data-urlencode name@filename",
			input: `curl --data-urlencode "field@data.txt" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertDataValues(t, "DataValues", r.DataValues, []DataValue{{Value: "field@data.txt", IsURLEncode: true}})
			},
		},
		{
			name:  "content-type preserved with explicit header",
			input: `curl -H "Content-Type: text/plain" -d "data" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertTrue(t, "HasContentType", r.HasContentType)
				assertEqual(t, "Headers[0].Name", r.Headers[0].Name, "Content-Type")
				assertEqual(t, "Headers[0].Value", r.Headers[0].Value, "text/plain")
			},
		},
		{
			name:    "missing URL",
			input:   "curl -X POST",
			wantErr: true,
		},
		{
			name:    "unknown flag",
			input:   "curl --unknown-flag https://example.com",
			wantErr: true,
		},
		{
			name:  "long flag with equals",
			input: `curl --request=POST https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Method", r.Method, "POST")
			},
		},
		{
			name:  "url flag",
			input: `curl --url https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "URL", r.URL, "https://example.com")
			},
		},
		{
			name:  "end of options marker",
			input: "curl -- https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "URL", r.URL, "https://example.com")
			},
		},
		{
			name:  "end of options with flags before",
			input: "curl -X POST -- https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Method", r.Method, "POST")
				assertEqual(t, "URL", r.URL, "https://example.com")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.check != nil && !tt.wantErr {
				tt.check(t, result)
			}
		})
	}
}

func TestParseAuth(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *Result)
	}{
		{
			name:  "basic auth",
			input: "curl -u user:pass https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "BasicAuth", r.BasicAuth, "user:pass")
			},
		},
		{
			name:  "basic auth long flag",
			input: "curl --user user:pass https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "BasicAuth", r.BasicAuth, "user:pass")
			},
		},
		{
			name:  "aws-sigv4",
			input: `curl --aws-sigv4 "aws:amz:us-east-1:s3" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "AWSSigv4", r.AWSSigv4, "aws:amz:us-east-1:s3")
			},
		},
		{
			name:  "oauth2-bearer",
			input: "curl --oauth2-bearer mytoken https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Bearer", r.Bearer, "mytoken")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			tt.check(t, result)
		})
	}
}

func TestParseTLS(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *Result)
	}{
		{
			name:  "insecure",
			input: "curl -k https://example.com",
			check: func(t *testing.T, r *Result) {
				assertTrue(t, "Insecure", r.Insecure)
			},
		},
		{
			name:  "insecure long",
			input: "curl --insecure https://example.com",
			check: func(t *testing.T, r *Result) {
				assertTrue(t, "Insecure", r.Insecure)
			},
		},
		{
			name:  "cacert",
			input: "curl --cacert /path/to/ca.pem https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "CACert", r.CACert, "/path/to/ca.pem")
			},
		},
		{
			name:  "cert short",
			input: "curl -E /path/to/cert.pem https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Cert", r.Cert, "/path/to/cert.pem")
			},
		},
		{
			name:  "cert long",
			input: "curl --cert /path/to/cert.pem https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Cert", r.Cert, "/path/to/cert.pem")
			},
		},
		{
			name:  "key",
			input: "curl --key /path/to/key.pem https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Key", r.Key, "/path/to/key.pem")
			},
		},
		{
			name:  "tlsv1.2",
			input: "curl --tlsv1.2 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "TLSVersion", r.TLSVersion, "1.2")
			},
		},
		{
			name:  "tlsv1.3",
			input: "curl --tlsv1.3 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "TLSVersion", r.TLSVersion, "1.3")
			},
		},
		{
			name:  "tlsv1",
			input: "curl --tlsv1 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "TLSVersion", r.TLSVersion, "1.0")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			tt.check(t, result)
		})
	}
}

func TestParseOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *Result)
	}{
		{
			name:  "output file",
			input: "curl -o output.txt https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Output", r.Output, "output.txt")
			},
		},
		{
			name:  "output long",
			input: "curl --output output.txt https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Output", r.Output, "output.txt")
			},
		},
		{
			name:  "remote name",
			input: "curl -O https://example.com/file.txt",
			check: func(t *testing.T, r *Result) {
				assertTrue(t, "RemoteName", r.RemoteName)
			},
		},
		{
			name:  "remote header name",
			input: "curl -J -O https://example.com/download",
			check: func(t *testing.T, r *Result) {
				assertTrue(t, "RemoteHeaderName", r.RemoteHeaderName)
				assertTrue(t, "RemoteName", r.RemoteName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			tt.check(t, result)
		})
	}
}

func TestParseNetwork(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *Result)
	}{
		{
			name:  "follow redirects",
			input: "curl -L https://example.com",
			check: func(t *testing.T, r *Result) {
				assertTrue(t, "FollowRedirects", r.FollowRedirects)
			},
		},
		{
			name:  "max redirects",
			input: "curl -L --max-redirs 5 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertTrue(t, "FollowRedirects", r.FollowRedirects)
				assertIntEqual(t, "MaxRedirects", r.MaxRedirects, 5)
			},
		},
		{
			name:  "max-time",
			input: "curl -m 30 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertFloatEqual(t, "Timeout", r.Timeout, 30)
			},
		},
		{
			name:  "max-time long",
			input: "curl --max-time 2.5 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertFloatEqual(t, "Timeout", r.Timeout, 2.5)
			},
		},
		{
			name:  "connect-timeout",
			input: "curl --connect-timeout 10 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertFloatEqual(t, "ConnectTimeout", r.ConnectTimeout, 10)
			},
		},
		{
			name:  "connect-timeout and max-time",
			input: "curl --connect-timeout 5 --max-time 30 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertFloatEqual(t, "ConnectTimeout", r.ConnectTimeout, 5)
				assertFloatEqual(t, "Timeout", r.Timeout, 30)
			},
		},
		{
			name:  "proxy",
			input: "curl -x http://proxy:8080 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Proxy", r.Proxy, "http://proxy:8080")
			},
		},
		{
			name:  "proxy long",
			input: "curl --proxy socks5://localhost:1080 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Proxy", r.Proxy, "socks5://localhost:1080")
			},
		},
		{
			name:  "unix socket",
			input: "curl --unix-socket /var/run/docker.sock http://unix/containers/json",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "UnixSocket", r.UnixSocket, "/var/run/docker.sock")
			},
		},
		{
			name:  "doh-url",
			input: "curl --doh-url https://1.1.1.1/dns-query https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "DoHURL", r.DoHURL, "https://1.1.1.1/dns-query")
			},
		},
		{
			name:  "retry",
			input: "curl --retry 3 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertIntEqual(t, "Retry", r.Retry, 3)
			},
		},
		{
			name:  "retry-delay",
			input: "curl --retry 3 --retry-delay 2 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertIntEqual(t, "Retry", r.Retry, 3)
				assertFloatEqual(t, "RetryDelay", r.RetryDelay, 2)
			},
		},
		{
			name:  "range",
			input: "curl -r 0-1023 https://example.com/file",
			check: func(t *testing.T, r *Result) {
				assertSliceEqual(t, "Ranges", r.Ranges, []string{"0-1023"})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			tt.check(t, result)
		})
	}
}

func TestParseHTTPVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *Result)
	}{
		{
			name:  "http1.0 short",
			input: "curl -0 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "HTTPVersion", r.HTTPVersion, "1.0")
			},
		},
		{
			name:  "http1.0 long",
			input: "curl --http1.0 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "HTTPVersion", r.HTTPVersion, "1.0")
			},
		},
		{
			name:  "http1.1",
			input: "curl --http1.1 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "HTTPVersion", r.HTTPVersion, "1.1")
			},
		},
		{
			name:  "http2",
			input: "curl --http2 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "HTTPVersion", r.HTTPVersion, "2")
			},
		},
		{
			name:  "http3",
			input: "curl --http3 https://example.com",
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "HTTPVersion", r.HTTPVersion, "3")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			tt.check(t, result)
		})
	}
}

func TestParseConvenienceHeaders(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *Result)
	}{
		{
			name:  "user-agent",
			input: `curl -A "MyBot/1.0" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "UserAgent", r.UserAgent, "MyBot/1.0")
			},
		},
		{
			name:  "user-agent long",
			input: `curl --user-agent "MyBot/1.0" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "UserAgent", r.UserAgent, "MyBot/1.0")
			},
		},
		{
			name:  "referer",
			input: `curl -e "https://google.com" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Referer", r.Referer, "https://google.com")
			},
		},
		{
			name:  "cookie",
			input: `curl -b "session=abc123" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Cookie", r.Cookie, "session=abc123")
			},
		},
		{
			name:  "cookie multiple values",
			input: `curl -b "session=abc123; user=john" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertEqual(t, "Cookie", r.Cookie, "session=abc123; user=john")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			tt.check(t, result)
		})
	}
}

func TestParseCookieFileRejection(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "cookie file short flag",
			input:   `curl -b cookies.txt https://example.com`,
			wantErr: true,
		},
		{
			name:    "cookie file long flag",
			input:   `curl --cookie cookies.txt https://example.com`,
			wantErr: true,
		},
		{
			name:    "cookie file with path",
			input:   `curl -b /path/to/cookies.txt https://example.com`,
			wantErr: true,
		},
		{
			name:  "cookie inline value accepted",
			input: `curl -b "name=value" https://example.com`,
		},
		{
			name:  "cookie inline long flag accepted",
			input: `curl --cookie "name=value" https://example.com`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseVerbosity(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *Result)
	}{
		{
			name:  "single verbose",
			input: "curl -v https://example.com",
			check: func(t *testing.T, r *Result) {
				assertIntEqual(t, "Verbose", r.Verbose, 1)
			},
		},
		{
			name:  "triple verbose",
			input: "curl -vvv https://example.com",
			check: func(t *testing.T, r *Result) {
				assertIntEqual(t, "Verbose", r.Verbose, 3)
			},
		},
		{
			name:  "verbose long",
			input: "curl --verbose https://example.com",
			check: func(t *testing.T, r *Result) {
				assertIntEqual(t, "Verbose", r.Verbose, 1)
			},
		},
		{
			name:  "silent",
			input: "curl -s https://example.com",
			check: func(t *testing.T, r *Result) {
				assertTrue(t, "Silent", r.Silent)
			},
		},
		{
			name:  "silent long",
			input: "curl --silent https://example.com",
			check: func(t *testing.T, r *Result) {
				assertTrue(t, "Silent", r.Silent)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			tt.check(t, result)
		})
	}
}

func TestParseBehavior(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "fail", input: "curl -f https://example.com"},
		{name: "fail long", input: "curl --fail https://example.com"},
		{name: "fail-with-body", input: "curl --fail-with-body https://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}
}

func TestParseNoOps(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "compressed", input: "curl --compressed https://example.com"},
		{name: "show-error", input: "curl -S https://example.com"},
		{name: "show-error long", input: "curl --show-error https://example.com"},
		{name: "no-buffer", input: "curl -N https://example.com"},
		{name: "no-buffer long", input: "curl --no-buffer https://example.com"},
		{name: "no-keepalive", input: "curl --no-keepalive https://example.com"},
		{name: "progress-bar", input: "curl -# https://example.com"},
		{name: "progress-bar long", input: "curl --progress-bar https://example.com"},
		{name: "no-progress-meter", input: "curl --no-progress-meter https://example.com"},
		{name: "netrc", input: "curl -n https://example.com"},
		{name: "netrc long", input: "curl --netrc https://example.com"},
		{name: "proto-default", input: "curl --proto-default https https://example.com"},
		{name: "proto-redir", input: "curl --proto-redir '=https' https://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if result.URL != "https://example.com" {
				t.Fatalf("expected URL to be https://example.com, got %s", result.URL)
			}
		})
	}
}

func TestParseComplexCommand(t *testing.T) {
	input := `curl -X POST \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer mytoken' \
  -d '{"key":"value","nested":{"a":1}}' \
  -k \
  --retry 3 \
  --retry-delay 1 \
  -L \
  --max-redirs 5 \
  https://api.example.com/v1/resource`

	result, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	assertEqual(t, "Method", result.Method, "POST")
	assertEqual(t, "URL", result.URL, "https://api.example.com/v1/resource")
	assertTrue(t, "Insecure", result.Insecure)
	assertTrue(t, "FollowRedirects", result.FollowRedirects)
	assertIntEqual(t, "Retry", result.Retry, 3)
	assertFloatEqual(t, "RetryDelay", result.RetryDelay, 1)
	assertIntEqual(t, "MaxRedirects", result.MaxRedirects, 5)

	if len(result.Headers) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(result.Headers))
	}
	assertDataValues(t, "DataValues", result.DataValues, []DataValue{{Value: `{"key":"value","nested":{"a":1}}`}})
}

func TestParseProto(t *testing.T) {
	t.Run("stores proto value", func(t *testing.T) {
		result, err := Parse("curl --proto '=https' https://example.com")
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		assertEqual(t, "AllowedProto", result.AllowedProto, "=https")
	})

	t.Run("proto with http,https", func(t *testing.T) {
		result, err := Parse("curl --proto 'http,https' https://example.com")
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		assertEqual(t, "AllowedProto", result.AllowedProto, "http,https")
	})
}

func TestParseAllowedProto(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantHTTP  bool
		wantHTTPS bool
	}{
		{"empty", "", true, true},
		{"exclusive https", "=https", false, true},
		{"exclusive http", "=http", true, false},
		{"exclusive both", "=http,https", true, true},
		{"add https", "+https", true, true},
		{"remove http", "-http", false, true},
		{"remove https", "-https", true, false},
		{"exclusive https only", "=https", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHTTP, gotHTTPS := ParseAllowedProto(tt.value)
			if gotHTTP != tt.wantHTTP {
				t.Errorf("allowHTTP = %v, want %v", gotHTTP, tt.wantHTTP)
			}
			if gotHTTPS != tt.wantHTTPS {
				t.Errorf("allowHTTPS = %v, want %v", gotHTTPS, tt.wantHTTPS)
			}
		})
	}
}

func TestParseDataBinary(t *testing.T) {
	input := `curl --data-binary @file.bin https://example.com`
	result, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	assertDataValues(t, "DataValues", result.DataValues, []DataValue{{Value: "@file.bin"}})
}

func TestParseMixedData(t *testing.T) {
	input := `curl -d "a=1" --data-raw "@not-a-file" -d "b=2" https://example.com`
	result, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	assertDataValues(t, "DataValues", result.DataValues, []DataValue{
		{Value: "a=1"},
		{Value: "@not-a-file", IsRaw: true},
		{Value: "b=2"},
	})
}

func TestParseHeadWithExplicitMethod(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		method string
	}{
		{
			name:   "-I alone uses HEAD",
			input:  "curl -I https://example.com",
			method: "HEAD",
		},
		{
			name:   "-X GET overrides -I",
			input:  "curl -I -X GET https://example.com",
			method: "GET",
		},
		{
			name:   "-X GET before -I still uses GET",
			input:  "curl -X GET -I https://example.com",
			method: "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			assertEqual(t, "Method", result.Method, tt.method)
		})
	}
}

func TestParseShortFlagInlineValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *Result)
	}{
		{
			name:  "short -d with inline value",
			input: `curl -d"key=value" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertDataValues(t, "DataValues", r.DataValues, []DataValue{{Value: "key=value"}})
			},
		},
		{
			name:  "combined short flags -vd with separate value",
			input: `curl -vd "data" https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertIntEqual(t, "Verbose", r.Verbose, 1)
				assertDataValues(t, "DataValues", r.DataValues, []DataValue{{Value: "data"}})
			},
		},
		{
			name:  "combined short flags -kv",
			input: `curl -kv https://example.com`,
			check: func(t *testing.T, r *Result) {
				assertTrue(t, "Insecure", r.Insecure)
				assertIntEqual(t, "Verbose", r.Verbose, 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			tt.check(t, result)
		})
	}
}

func TestURLEncodeValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want DataValue
	}{
		{
			name: "bare content",
			in:   "hello world",
			want: DataValue{Value: "hello+world"},
		},
		{
			name: "=content",
			in:   "=hello world",
			want: DataValue{Value: "hello+world"},
		},
		{
			name: "name=content",
			in:   "key=hello world",
			want: DataValue{Value: "key=hello+world"},
		},
		{
			name: "@filename passthrough",
			in:   "@myfile.txt",
			want: DataValue{Value: "@myfile.txt", IsURLEncode: true},
		},
		{
			name: "name@filename passthrough",
			in:   "field@data.txt",
			want: DataValue{Value: "field@data.txt", IsURLEncode: true},
		},
		{
			name: "name=content with @ in content",
			in:   "email=user@example.com",
			want: DataValue{Value: "email=user%40example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := urlEncodeValue(tt.in)
			if err != nil {
				t.Fatalf("urlEncodeValue(%q) error = %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("urlEncodeValue(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseDataUrlencodeEqualsContent(t *testing.T) {
	// "=content" format: leading = means URL-encode the content after it.
	result, err := Parse(`curl --data-urlencode "=hello world" https://example.com`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	assertDataValues(t, "DataValues", result.DataValues, []DataValue{{Value: "hello+world"}})
}

func TestParseURLConflicts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "positional URL then --url errors",
			input:   "curl https://a.com --url https://b.com",
			wantErr: true,
		},
		{
			name:    "--url then positional URL errors",
			input:   "curl --url https://a.com https://b.com",
			wantErr: true,
		},
		{
			name:    "two positional URLs errors",
			input:   "curl https://a.com https://b.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseDataAndUploadFileConflict(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "-d with -T errors",
			input:   `curl -d "data" -T file.txt https://example.com`,
			wantErr: true,
		},
		{
			name:    "-T with -d errors",
			input:   `curl -T file.txt -d "data" https://example.com`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func assertEqual(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}

func assertIntEqual(t *testing.T, name string, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %d, want %d", name, got, want)
	}
}

func assertFloatEqual(t *testing.T, name string, got, want float64) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %f, want %f", name, got, want)
	}
}

func assertTrue(t *testing.T, name string, got bool) {
	t.Helper()
	if !got {
		t.Fatalf("%s = false, want true", name)
	}
}

func assertSliceEqual(t *testing.T, name string, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}

func assertDataValues(t *testing.T, name string, got []DataValue, want []DataValue) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}
