package fetch

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/digest"
)

// Check the server-side calculation independently of the Digest generator.
func validRedirectDigest(req *http.Request, realm, nonce string) bool {
	auth := req.Header.Get("Authorization")
	param := func(key string) string { return digestAuthParam(auth, key) }
	hash := func(s string) string { return fmt.Sprintf("%x", md5.Sum([]byte(s))) }
	if param("username") != "user" || param("realm") != realm || param("nonce") != nonce || param("uri") != req.URL.RequestURI() || param("qop") != "auth" {
		return false
	}
	ha1 := hash("user:" + realm + ":pass")
	ha2 := hash(req.Method + ":" + req.URL.RequestURI())
	return param("response") == hash(ha1+":"+nonce+":"+param("nc")+":"+param("cnonce")+":auth:"+ha2)
}

func runDigestRedirect(t *testing.T, method, target string, source io.Reader) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, method, target, source)
	if err != nil {
		t.Fatal(err)
	}
	c := client.NewClient(client.ClientConfig{})
	t.Cleanup(func() { _ = c.Close() })
	resp, err := doOnce(&Request{Digest: &core.KeyVal[string]{Key: "user", Val: "pass"}}, c, req, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestDigestAuthenticatedRedirect(t *testing.T) {
	for _, tt := range []struct {
		name, method, finalMethod, domain, finalRealm string
		status, finalHits                             int
	}{
		{name: "same challenge", method: "GET", finalMethod: "GET", status: http.StatusFound, finalHits: 1},
		{name: "POST becomes GET", method: "POST", finalMethod: "GET", status: http.StatusSeeOther, finalHits: 1},
		{name: "POST keeps body", method: "POST", finalMethod: "POST", status: http.StatusTemporaryRedirect, finalHits: 1},
		{name: "PUT keeps method", method: "PUT", finalMethod: "PUT", status: http.StatusFound, finalHits: 1},
		{name: "new realm", method: "GET", finalMethod: "GET", status: http.StatusFound, finalRealm: "other", finalHits: 2},
		{name: "outside protection space", method: "GET", finalMethod: "GET", status: http.StatusFound, domain: "/start", finalRealm: "other", finalHits: 2},
		{name: "inside protection space", method: "GET", finalMethod: "GET", status: http.StatusFound, domain: "/start /final", finalHits: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			startHits, finalHits := 0, 0
			finalRealm := tt.finalRealm
			if finalRealm == "" {
				finalRealm = "test"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				realm, domain := "test", tt.domain
				if req.URL.Path == "/final" {
					finalHits++
					realm, domain = finalRealm, ""
					if tt.domain == "/start" && finalHits == 1 && req.Header.Get("Authorization") != "" {
						t.Error("authorization forwarded outside the challenge protection space")
					}
				} else {
					startHits++
				}
				if !validRedirectDigest(req, realm, "nonce") {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm=%q, nonce="nonce", qop="auth", domain=%q`, realm, domain))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if req.URL.Path == "/start" {
					http.Redirect(w, req, "/final?token=1", tt.status)
					return
				}
				if req.Method != tt.finalMethod {
					t.Errorf("method = %s, want %s", req.Method, tt.finalMethod)
				}
				body, _ := io.ReadAll(req.Body)
				wantBody := "payload"
				if tt.finalMethod == "GET" {
					wantBody = ""
				}
				if string(body) != wantBody {
					t.Errorf("body = %q, want %q", body, wantBody)
				}
				if finalHits == 1 && digestAuthParam(req.Header.Get("Authorization"), "nc") != "00000002" {
					t.Error("redirect did not increment the nonce count")
				}
			}))
			defer server.Close()
			var source io.Reader
			if tt.method != "GET" {
				source = strings.NewReader("payload")
			}
			resp := runDigestRedirect(t, tt.method, server.URL+"/start", source)
			if resp.StatusCode != http.StatusOK || startHits != 2 || finalHits != tt.finalHits {
				t.Fatalf("status=%d, start hits=%d, final hits=%d; want 200, 2, %d", resp.StatusCode, startHits, finalHits, tt.finalHits)
			}
		})
	}
}

func TestDigestRedirectChallengeLimits(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprintf("stale=%v", stale), func(t *testing.T) {
			counts := map[string]int{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				counts[req.URL.Path]++
				if req.URL.Path == "/start" && counts["/start"] == 2 {
					http.Redirect(w, req, "/final", http.StatusFound)
					return
				}
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="test", nonce="nonce", qop="auth", stale=%v`, stale))
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()
			resp := runDigestRedirect(t, "GET", server.URL+"/start", nil)
			wantFinal := 2
			if stale {
				wantFinal++
			}
			if resp.StatusCode != http.StatusUnauthorized || counts["/start"] != 2 || counts["/final"] != wantFinal {
				t.Fatalf("status=%d, counts=%v, want 401 and start=2, final=%d", resp.StatusCode, counts, wantFinal)
			}
		})
	}
}

func TestDigestRedirectDoesNotRestoreCrossOriginCredentials(t *testing.T) {
	for _, returnToOrigin := range []bool{false, true} {
		t.Run(fmt.Sprintf("return=%v", returnToOrigin), func(t *testing.T) {
			var sourceURL string
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Header.Get("Authorization") != "" {
					t.Error("cross-origin request received authorization")
				}
				if returnToOrigin {
					http.Redirect(w, req, sourceURL+"/final", http.StatusFound)
					return
				}
				w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="nonce", qop="auth"`)
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer other.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/start" && validRedirectDigest(req, "test", "nonce") {
					http.Redirect(w, req, other.URL, http.StatusFound)
					return
				}
				if req.URL.Path == "/final" && req.Header.Get("Authorization") != "" {
					t.Error("authorization restored after returning to origin")
				}
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="test", nonce="nonce", qop="auth", domain=%q`, other.URL+"/"))
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()
			sourceURL = server.URL
			resp := runDigestRedirect(t, "GET", server.URL+"/start", nil)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
}

func TestDigestRedirectBoundsDistinctTargets(t *testing.T) {
	challenges := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") == "" {
			challenges++
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="test", nonce="nonce", qop="auth", domain=%q`, req.URL.Path))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		n, _ := strconv.Atoi(strings.TrimPrefix(req.URL.Path, "/"))
		http.Redirect(w, req, fmt.Sprintf("/%d", n+1), http.StatusFound)
	}))
	defer server.Close()
	resp := runDigestRedirect(t, "GET", server.URL+"/0", nil)
	if resp.StatusCode != http.StatusUnauthorized || challenges != maxDigestChallengeRetries+1 {
		t.Fatalf("status=%d, challenges=%d, want 401 and %d", resp.StatusCode, challenges, maxDigestChallengeRetries+1)
	}
}

func TestDigestRedirectStaleLimitIsPerTarget(t *testing.T) {
	counts := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		counts[req.URL.Path]++
		n := counts[req.URL.Path]
		if n < 3 {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="test", nonce=%q, qop="auth", stale=%v`, req.URL.Path+strconv.Itoa(n), n == 2))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !validRedirectDigest(req, "test", req.URL.Path+"2") {
			t.Error("request did not authenticate with its target's fresh nonce")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if req.URL.Path == "/start" {
			http.Redirect(w, req, "/final", http.StatusFound)
		}
	}))
	defer server.Close()
	resp := runDigestRedirect(t, "GET", server.URL+"/start", nil)
	if resp.StatusCode != http.StatusOK || counts["/start"] != 3 || counts["/final"] != 3 {
		t.Fatalf("status=%d, counts=%v, want 200 and three requests per target", resp.StatusCode, counts)
	}
}

func TestDigestRedirectLoopDoesNotResetTargetLimit(t *testing.T) {
	counts := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		counts[req.URL.Path]++
		if !validRedirectDigest(req, "test", "nonce") {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="test", nonce="nonce", qop="auth", domain=%q`, req.URL.Path))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next := "/start"
		if req.URL.Path == "/start" {
			next = "/final"
		}
		http.Redirect(w, req, next, http.StatusFound)
	}))
	defer server.Close()
	resp := runDigestRedirect(t, "GET", server.URL+"/start", nil)
	if resp.StatusCode != http.StatusUnauthorized || counts["/start"] != 3 || counts["/final"] != 2 {
		t.Fatalf("status=%d, counts=%v, want 401, start=3, final=2", resp.StatusCode, counts)
	}
}

func TestDigestRedirectChallengeTargetIncludesMethodAndQuery(t *testing.T) {
	for _, changeMethod := range []bool{false, true} {
		t.Run(fmt.Sprintf("change method=%v", changeMethod), func(t *testing.T) {
			initialHits, finalHits := 0, 0
			method := "GET"
			if changeMethod {
				method = "POST"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				initial := req.URL.RawQuery == "step=1"
				if changeMethod {
					initial = req.Method == "POST"
				}
				if initial {
					initialHits++
				} else {
					finalHits++
				}
				if !validRedirectDigest(req, "test", "nonce") {
					w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="nonce", qop="auth", domain="/other"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if initial {
					next := "/resource?step=2"
					if changeMethod {
						next = "/resource?step=1"
					}
					http.Redirect(w, req, next, http.StatusSeeOther)
				}
			}))
			defer server.Close()
			resp := runDigestRedirect(t, method, server.URL+"/resource?step=1", nil)
			if resp.StatusCode != http.StatusOK || initialHits != 2 || finalHits != 2 {
				t.Fatalf("status=%d, initial hits=%d, final hits=%d; want 200, 2, 2", resp.StatusCode, initialHits, finalHits)
			}
		})
	}
}

func TestDigestChallengeProtectionSpace(t *testing.T) {
	for _, tt := range []struct {
		domain, next string
		want         bool
	}{
		{"", "https://example.com/final", true},
		{"/start /final", "https://example.com/final?x=1", true},
		{"https://example.com:443/final", "https://example.com/final", true},
		{"/final?x=1", "https://example.com/final?x=2", false},
		{"/escaped%2F", "https://example.com/escaped%2Ffinal", true},
		{"/start", "https://example.com/final", false},
		{"", "http://example.com/final", false},
		{"https://other.test/", "https://other.test/final", false},
		{"relative //example.com/final /bad%zz", "https://example.com/final", false},
	} {
		t.Run(tt.domain+" -> "+tt.next, func(t *testing.T) {
			chal := &digest.Challenge{Domain: tt.domain}
			got := digestChallengeApplies(chal, mustParseURL("https://example.com/start"), mustParseURL(tt.next))
			if got != tt.want {
				t.Fatalf("applies = %v, want %v", got, tt.want)
			}
		})
	}
}
