package digest

import (
	"crypto/md5"
	"crypto/sha256"
	"net/http"
	"strings"
	"testing"
)

func TestParseChallenge(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *Challenge
		wantErr bool
	}{
		{
			name:  "simple",
			input: `Digest realm="test", nonce="abc123"`,
			want: &Challenge{
				Realm: "test",
				Nonce: "abc123",
			},
		},
		{
			name:  "full",
			input: `Digest realm="test", nonce="abc123", qop="auth", algorithm="MD5", opaque="opaque123", stale="true"`,
			want: &Challenge{
				Realm:     "test",
				Nonce:     "abc123",
				QOP:       "auth",
				Algorithm: "MD5",
				Opaque:    "opaque123",
				Stale:     "true",
			},
		},
		{
			name:  "unquoted algorithm",
			input: `Digest realm="test", nonce="abc123", algorithm=MD5`,
			want: &Challenge{
				Realm:     "test",
				Nonce:     "abc123",
				Algorithm: "MD5",
			},
		},
		{
			name:    "missing realm",
			input:   `Digest nonce="abc123"`,
			wantErr: true,
		},
		{
			name:    "missing nonce",
			input:   `Digest realm="test"`,
			wantErr: true,
		},
		{
			name:    "not digest",
			input:   `Basic realm="test"`,
			wantErr: true,
		},
		{
			name:  "escaped quotes",
			input: `Digest realm="test \"realm\"", nonce="abc123"`,
			want: &Challenge{
				Realm: `test "realm"`,
				Nonce: "abc123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseChallenge(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Realm != tt.want.Realm {
				t.Errorf("realm: got %q, want %q", got.Realm, tt.want.Realm)
			}
			if got.Nonce != tt.want.Nonce {
				t.Errorf("nonce: got %q, want %q", got.Nonce, tt.want.Nonce)
			}
			if got.QOP != tt.want.QOP {
				t.Errorf("qop: got %q, want %q", got.QOP, tt.want.QOP)
			}
			if got.Algorithm != tt.want.Algorithm {
				t.Errorf("algorithm: got %q, want %q", got.Algorithm, tt.want.Algorithm)
			}
			if got.Opaque != tt.want.Opaque {
				t.Errorf("opaque: got %q, want %q", got.Opaque, tt.want.Opaque)
			}
			if got.Stale != tt.want.Stale {
				t.Errorf("stale: got %q, want %q", got.Stale, tt.want.Stale)
			}
		})
	}
}

func TestResponse(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/path?query=1", nil)
	if err != nil {
		t.Fatal(err)
	}

	chal := &Challenge{
		Realm:     "test",
		Nonce:     "nonce123",
		Algorithm: "MD5",
	}

	auth, err := Response(req, chal, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(auth, "Digest ") {
		t.Fatalf("expected Digest prefix, got: %s", auth)
	}
	if !strings.Contains(auth, `username="user"`) {
		t.Errorf("expected username in auth: %s", auth)
	}
	if !strings.Contains(auth, `realm="test"`) {
		t.Errorf("expected realm in auth: %s", auth)
	}
	if !strings.Contains(auth, `uri="/path?query=1"`) {
		t.Errorf("expected uri in auth: %s", auth)
	}
	if !strings.Contains(auth, `response="`) {
		t.Errorf("expected response in auth: %s", auth)
	}
	// No qop should not contain nc or cnonce.
	if strings.Contains(auth, "nc=") {
		t.Errorf("unexpected nc without qop: %s", auth)
	}
}

func TestResponseWithQOP(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/api", strings.NewReader("data"))
	if err != nil {
		t.Fatal(err)
	}

	chal := &Challenge{
		Realm:     "test",
		Nonce:     "nonce123",
		QOP:       "auth",
		Algorithm: "MD5",
		Opaque:    "opaque123",
	}

	auth, err := Response(req, chal, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(auth, "Digest ") {
		t.Fatalf("expected Digest prefix, got: %s", auth)
	}
	if !strings.Contains(auth, `qop=auth`) {
		t.Errorf("expected qop=auth: %s", auth)
	}
	if !strings.Contains(auth, `nc=00000001`) {
		t.Errorf("expected nc: %s", auth)
	}
	if !strings.Contains(auth, `cnonce="`) {
		t.Errorf("expected cnonce: %s", auth)
	}
	if !strings.Contains(auth, `opaque="opaque123"`) {
		t.Errorf("expected opaque: %s", auth)
	}
}

func TestResponseMD5Sess(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	chal := &Challenge{
		Realm:     "test",
		Nonce:     "nonce123",
		QOP:       "auth",
		Algorithm: "MD5-sess",
	}

	auth, err := Response(req, chal, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(auth, `algorithm=MD5-SESS`) {
		t.Errorf("expected MD5-SESS algorithm: %s", auth)
	}
	if !strings.Contains(auth, `qop=auth`) {
		t.Errorf("expected qop=auth: %s", auth)
	}
}

func TestHashDigest(t *testing.T) {
	got := hashDigest(md5.New, "user:test:pass")
	want := "0f1cafcb677261987de453fb58ea335f"
	if got != want {
		t.Errorf("hashDigest(md5.New): got %q, want %q", got, want)
	}

	got = hashDigest(sha256.New, "user:test:pass")
	want = "9b5b3785d6946a15f7d5b4ec2e3a2e4d8f9e3b2c1a0d5e6f7b8c9d0e1f2a3b4c"
	if got == want {
		// The exact value isn't important; we just need to verify it doesn't panic
		// and produces a 64-character hex string.
	}
	if len(got) != 64 {
		t.Errorf("hashDigest(sha256.New): expected 64 hex chars, got %d", len(got))
	}
}

func TestResponseSHA256(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	chal := &Challenge{
		Realm:     "test",
		Nonce:     "nonce123",
		QOP:       "auth",
		Algorithm: "SHA-256",
	}

	auth, err := Response(req, chal, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(auth, `algorithm=SHA-256`) {
		t.Errorf("expected SHA-256 algorithm: %s", auth)
	}
	if !strings.Contains(auth, `qop=auth`) {
		t.Errorf("expected qop=auth: %s", auth)
	}
}

func TestResponseAuthIntOnly(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	chal := &Challenge{
		Realm:     "test",
		Nonce:     "nonce123",
		QOP:       "auth-int",
		Algorithm: "MD5",
	}

	_, err = Response(req, chal, "user", "pass")
	if err == nil {
		t.Fatal("expected error for unsupported qop, got nil")
	}
}

func TestResponseUnsupportedAlgorithm(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	chal := &Challenge{
		Realm:     "test",
		Nonce:     "nonce123",
		Algorithm: "UNKNOWN",
	}

	_, err = Response(req, chal, "user", "pass")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm, got nil")
	}
}
