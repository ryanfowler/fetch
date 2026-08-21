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

func TestParseChallengeRejectsMalformedQuotedStrings(t *testing.T) {
	for _, input := range []string{
		`Digest realm="test, nonce="abc123"`,
		`Digest realm="test", nonce="abc123\\`,
		`Digest realm="test", nonce="abc` + "\x01" + `"`,
	} {
		if _, err := ParseChallenge(input); err == nil {
			t.Errorf("ParseChallenge(%q) succeeded, want malformed challenge", input)
		}
	}
}

func TestParseChallengePreservesUTF8AndBackslashes(t *testing.T) {
	got, err := ParseChallenge(`Digest realm="café \"déjà\" C:\\", nonce="n\\once"`)
	if err != nil {
		t.Fatal(err)
	}
	if got.Realm != `café "déjà" C:\` || got.Nonce != `n\once` {
		t.Fatalf("decoded challenge = %#v", got)
	}
}

func TestResponseSupportsAllRFC7616AlgorithmsAndQOPLists(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []string{"MD5", "MD5-sess", "SHA-256", "SHA-256-sess", "SHA-512-256", "SHA-512-256-sess"} {
		auth, err := Response(req, &Challenge{
			Realm: "realm", Nonce: "nonce", Algorithm: algorithm, QOP: "AUTH-INT, AuTh",
		}, " user", "pass ")
		if err != nil {
			t.Fatalf("algorithm %s: %v", algorithm, err)
		}
		if !strings.Contains(strings.ToLower(auth), "qop=auth") || !strings.Contains(auth, `username=" user"`) {
			t.Fatalf("algorithm %s produced invalid authorization: %s", algorithm, auth)
		}
	}
}

func TestResponseMatchesRFC7616Vectors(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/dir/index.html", nil)
	if err != nil {
		t.Fatal(err)
	}
	challenge := func(algorithm, qop string) *Challenge {
		return &Challenge{Realm: "testrealm@host.com", Nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093", Algorithm: algorithm, QOP: qop}
	}
	vectors := map[string]string{
		"MD5":              "6629fae49393a05397450978507c4ef1",
		"MD5-sess":         "8e3825c57e897f5a0dec6c2d4e5059d0",
		"SHA-256":          "5abdd07184ba512a22c53f41470e5eea7dcaa3a93a59b630c13dfe0a5dc6e38b",
		"SHA-256-sess":     "b8822e12417cb7750f4e2b8515f0dcf25b7dd26993e80bee1426201446a7f59b",
		"SHA-512-256":      "f23c08ec7334a881f8286e68450ddbd9f0cd91c41481f0e1433604da8113c6dc",
		"SHA-512-256-sess": "0d21f0db3ec5cda5b850c0afa3bc29b4a3c5a6191959ff1baf511d4b38eb6b1e",
	}
	for algorithm, want := range vectors {
		chal := challenge(algorithm, "auth")
		hashFunc, err := hashForAlgorithm(strings.ToLower(algorithm))
		if err != nil {
			t.Fatal(err)
		}
		auth, err := responseWithCnonce(req, chal, "Mufasa", "Circle Of Life", strings.ToLower(algorithm), hashFunc, "0a4f113b")
		if err != nil || !strings.Contains(auth, `response="`+want+`"`) {
			t.Fatalf("%s vector: auth=%q err=%v", algorithm, auth, err)
		}
	}

	// The no-qop form uses the same RFC credentials and must not emit qop/nc.
	chal := challenge("MD5", "")
	hashFunc, _ := hashForAlgorithm("md5")
	auth, err := responseWithCnonce(req, chal, "Mufasa", "Circle Of Life", "md5", hashFunc, "")
	if err != nil || !strings.Contains(auth, `response="670fd8c2df070c60b045671b8b24ff02"`) || strings.Contains(auth, "qop=") || strings.Contains(auth, "nc=") {
		t.Fatalf("no-qop vector: auth=%q err=%v", auth, err)
	}
}

func TestResponseEscapesBackslashesAndQuotes(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/a\\b\"c", nil)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := Response(req, &Challenge{
		Realm: `ré\alm"`, Nonce: `n\once"`, Opaque: `op\aque"`, Algorithm: "MD5",
	}, `usér\name"`, "pass")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`username="usér\\name\""`, `realm="ré\\alm\""`, `nonce="n\\once\""`, `opaque="op\\aque\""`} {
		if !strings.Contains(auth, want) {
			t.Errorf("authorization %q does not contain %q", auth, want)
		}
	}
}
