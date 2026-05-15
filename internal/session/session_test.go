package session

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsValidName(t *testing.T) {
	valid := []string{
		"default",
		"api-prod",
		"my_session",
		"Session1",
		"a",
		"a-b_c-123",
	}
	for _, name := range valid {
		if !IsValidName(name) {
			t.Errorf("expected %q to be valid", name)
		}
	}

	invalid := []string{
		"",
		"../etc/passwd",
		"session name",
		"session/name",
		"session.name",
		"session\x00name",
		".hidden",
	}
	for _, name := range invalid {
		if IsValidName(name) {
			t.Errorf("expected %q to be invalid", name)
		}
	}
}

func TestLoadSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	// Load a non-existent session: should return empty.
	sess, err := Load("test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.Name != "test" {
		t.Fatalf("unexpected name: %s", sess.Name)
	}
	if len(sess.Cookies) != 0 {
		t.Fatalf("expected no cookies, got %d", len(sess.Cookies))
	}

	// Add cookies and save.
	sess.Cookies = []SessionCookie{
		{
			Name:     "session_id",
			Value:    "abc123",
			Domain:   "example.com",
			Path:     "/",
			Expires:  time.Now().Add(time.Hour).Truncate(time.Second),
			Secure:   true,
			HttpOnly: true,
		},
		{
			Name:   "theme",
			Value:  "dark",
			Domain: "example.com",
			Path:   "/",
		},
	}
	if err := sess.Save(); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	// Verify file exists.
	path := filepath.Join(dir, "test.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("session file not found: %v", err)
	}

	// Load again and verify.
	sess2, err := Load("test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sess2.Cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(sess2.Cookies))
	}
	if sess2.Cookies[0].Name != "session_id" || sess2.Cookies[0].Value != "abc123" {
		t.Fatalf("unexpected cookie: %+v", sess2.Cookies[0])
	}
	if sess2.Cookies[0].Secure != true || sess2.Cookies[0].HttpOnly != true {
		t.Fatalf("unexpected cookie flags: %+v", sess2.Cookies[0])
	}
	if sess2.Cookies[1].Name != "theme" || sess2.Cookies[1].Value != "dark" {
		t.Fatalf("unexpected cookie: %+v", sess2.Cookies[1])
	}
}

func TestSaveOverwritesExistingSessionFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	sess, err := Load("test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sess.Cookies = []SessionCookie{{Name: "token", Value: "old", Domain: "example.com", Path: "/"}}
	if err := sess.Save(); err != nil {
		t.Fatalf("first save failed: %v", err)
	}

	sess.Cookies = []SessionCookie{{Name: "token", Value: "new", Domain: "example.com", Path: "/"}}
	if err := sess.Save(); err != nil {
		t.Fatalf("second save failed: %v", err)
	}

	reloaded, err := Load("test")
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if len(reloaded.Cookies) != 1 || reloaded.Cookies[0].Value != "new" {
		t.Fatalf("reloaded cookies = %+v, want updated value", reloaded.Cookies)
	}
}

func TestExpiredCookiesFiltered(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	sess, err := Load("expiry-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sess.Cookies = []SessionCookie{
		{
			Name:    "valid",
			Value:   "yes",
			Domain:  "example.com",
			Path:    "/",
			Expires: time.Now().Add(time.Hour),
		},
		{
			Name:    "expired",
			Value:   "no",
			Domain:  "example.com",
			Path:    "/",
			Expires: time.Now().Add(-time.Hour),
		},
		{
			Name:   "no-expiry",
			Value:  "session",
			Domain: "example.com",
			Path:   "/",
		},
	}
	if err := sess.Save(); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	// Reload: expired cookie should be gone.
	sess2, err := Load("expiry-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sess2.Cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(sess2.Cookies))
	}
	for _, c := range sess2.Cookies {
		if c.Name == "expired" {
			t.Fatal("expired cookie should have been filtered")
		}
	}
}

func TestSessionJar(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	sess, err := Load("jar-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jar := sess.Jar()
	u, _ := url.Parse("http://example.com/path")

	// Set cookies via the jar.
	jar.SetCookies(u, []*http.Cookie{
		{Name: "a", Value: "1"},
		{Name: "b", Value: "2"},
	})

	// Cookies should be retrievable from the jar.
	cookies := jar.Cookies(u)
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies from jar, got %d", len(cookies))
	}

	// Cookies should be recorded in the session.
	if len(sess.Cookies) != 2 {
		t.Fatalf("expected 2 session cookies, got %d", len(sess.Cookies))
	}

	// Save and reload.
	if err := sess.Save(); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	sess2, err := Load("jar-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sess2.Cookies) != 2 {
		t.Fatalf("expected 2 cookies after reload, got %d", len(sess2.Cookies))
	}
}

func TestSessionJarDoesNotPersistForeignDomainCookie(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	sess, err := Load("foreign-domain-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	origin, _ := url.Parse("https://example.com/")
	jar := sess.Jar()
	jar.SetCookies(origin, []*http.Cookie{
		{Name: "token", Value: "secret", Domain: "evil.com"},
	})

	if cookies := jar.Cookies(origin); len(cookies) != 0 {
		t.Fatalf("origin cookies = %+v, want none", cookies)
	}
	if len(sess.Cookies) != 0 {
		t.Fatalf("foreign-domain cookie was persisted: %+v", sess.Cookies)
	}
	if err := sess.Save(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	reloaded, err := Load("foreign-domain-test")
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	jar = reloaded.Jar()
	evil, _ := url.Parse("https://evil.com/")
	if cookies := jar.Cookies(evil); len(cookies) != 0 {
		t.Fatalf("foreign-domain cookie leaked after reload: %+v", cookies)
	}
}

func TestSessionJarRejectsPublicSuffixCookie(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	sess, err := Load("public-suffix-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	origin, _ := url.Parse("https://example.com/")
	jar := sess.Jar()
	jar.SetCookies(origin, []*http.Cookie{
		{Name: "token", Value: "secret", Domain: "com"},
	})

	if cookies := jar.Cookies(origin); len(cookies) != 0 {
		t.Fatalf("public-suffix cookie accepted by jar: %+v", cookies)
	}
	if len(sess.Cookies) != 0 {
		t.Fatalf("public-suffix cookie was persisted: %+v", sess.Cookies)
	}
}

func TestSessionJarReloadUsesRFCDefaultPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	sess, err := Load("default-path-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	login, _ := url.Parse("https://example.com/app/login")
	jar := sess.Jar()
	jar.SetCookies(login, []*http.Cookie{
		{Name: "token", Value: "secret"},
	})

	if len(sess.Cookies) != 1 {
		t.Fatalf("expected 1 session cookie, got %d", len(sess.Cookies))
	}
	if sess.Cookies[0].Path != "/app" {
		t.Fatalf("persisted path = %q, want /app", sess.Cookies[0].Path)
	}
	if err := sess.Save(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	reloaded, err := Load("default-path-test")
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	jar = reloaded.Jar()

	appPage, _ := url.Parse("https://example.com/app/page")
	appCookies := cookieNames(jar.Cookies(appPage))
	if !appCookies["token"] {
		t.Fatalf("/app/page cookies = %v, want token", appCookies)
	}

	other, _ := url.Parse("https://example.com/other")
	otherCookies := cookieNames(jar.Cookies(other))
	if otherCookies["token"] {
		t.Fatalf("/other received default-path cookie after reload: %v", otherCookies)
	}
}

func TestSessionJarReloadPreservesHostOnlyCookies(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	sess, err := Load("host-only-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	origin, _ := url.Parse("https://example.com/")
	subdomain, _ := url.Parse("https://api.example.com/")
	jar := sess.Jar()
	jar.SetCookies(origin, []*http.Cookie{
		{Name: "host", Value: "only"},
		{Name: "domain", Value: "wide", Domain: "example.com"},
	})

	if len(sess.Cookies) != 2 {
		t.Fatalf("expected 2 session cookies, got %d", len(sess.Cookies))
	}
	for _, c := range sess.Cookies {
		switch c.Name {
		case "host":
			if !c.HostOnly {
				t.Fatalf("host-only cookie was not marked host-only: %+v", c)
			}
		case "domain":
			if c.HostOnly {
				t.Fatalf("domain cookie was marked host-only: %+v", c)
			}
		}
	}

	if err := sess.Save(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	reloaded, err := Load("host-only-test")
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	jar = reloaded.Jar()

	originCookies := cookieNames(jar.Cookies(origin))
	if !originCookies["host"] || !originCookies["domain"] {
		t.Fatalf("origin cookies = %v, want host and domain cookies", originCookies)
	}

	subdomainCookies := cookieNames(jar.Cookies(subdomain))
	if subdomainCookies["host"] {
		t.Fatalf("subdomain received host-only cookie after reload: %v", subdomainCookies)
	}
	if !subdomainCookies["domain"] {
		t.Fatalf("subdomain cookies = %v, want domain cookie", subdomainCookies)
	}
}

func TestSessionJarUpdatesExisting(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	sess, err := Load("update-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jar := sess.Jar()
	u, _ := url.Parse("http://example.com/")

	// Set initial cookie.
	jar.SetCookies(u, []*http.Cookie{
		{Name: "token", Value: "old"},
	})
	if len(sess.Cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(sess.Cookies))
	}

	// Update the same cookie.
	jar.SetCookies(u, []*http.Cookie{
		{Name: "token", Value: "new"},
	})
	if len(sess.Cookies) != 1 {
		t.Fatalf("expected 1 cookie after update, got %d", len(sess.Cookies))
	}
	if sess.Cookies[0].Value != "new" {
		t.Fatalf("expected updated value, got %s", sess.Cookies[0].Value)
	}
}

func cookieNames(cookies []*http.Cookie) map[string]bool {
	names := make(map[string]bool, len(cookies))
	for _, c := range cookies {
		names[c.Name] = true
	}
	return names
}

func TestSessionJarPersistsMaxAgeAsExpiry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	sess, err := Load("max-age-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jar := sess.Jar()
	u, _ := url.Parse("http://example.com/")

	before := time.Now()
	jar.SetCookies(u, []*http.Cookie{
		{Name: "short", Value: "lived", MaxAge: 60},
	})
	after := time.Now()

	if len(sess.Cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(sess.Cookies))
	}
	expires := sess.Cookies[0].Expires
	if expires.IsZero() {
		t.Fatal("expected Max-Age cookie to persist with an absolute expiry")
	}
	if expires.Before(before.Add(60*time.Second)) || expires.After(after.Add(60*time.Second)) {
		t.Fatalf("expires = %s, want about 60s after SetCookies", expires)
	}

	if err := sess.Save(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	reloaded, err := Load("max-age-test")
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if len(reloaded.Cookies) != 1 {
		t.Fatalf("expected 1 cookie after reload, got %d", len(reloaded.Cookies))
	}
	if reloaded.Cookies[0].Expires.IsZero() {
		t.Fatal("expected reloaded Max-Age cookie to keep its expiry")
	}
}

func TestSessionJarMaxAgeOverridesExpires(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	sess, err := Load("max-age-expires-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jar := sess.Jar()
	u, _ := url.Parse("http://example.com/")

	jar.SetCookies(u, []*http.Cookie{
		{
			Name:    "token",
			Value:   "live",
			MaxAge:  60,
			Expires: time.Now().Add(-time.Hour),
		},
	})

	if len(sess.Cookies) != 1 {
		t.Fatalf("expected Max-Age to override expired Expires, got %+v", sess.Cookies)
	}
	if sess.Cookies[0].Expires.IsZero() || !sess.Cookies[0].Expires.After(time.Now()) {
		t.Fatalf("expected future expiry from Max-Age, got %s", sess.Cookies[0].Expires)
	}
}

func TestSessionJarDeletedCookieNotPersisted(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	sess, err := Load("delete-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jar := sess.Jar()
	u, _ := url.Parse("https://example.com/")

	jar.SetCookies(u, []*http.Cookie{
		{Name: "token", Value: "live"},
	})
	if err := sess.Save(); err != nil {
		t.Fatalf("initial save failed: %v", err)
	}

	sess, err = Load("delete-test")
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if len(sess.Cookies) != 1 {
		t.Fatalf("expected 1 cookie after reload, got %d", len(sess.Cookies))
	}

	jar = sess.Jar()
	jar.SetCookies(u, []*http.Cookie{
		{Name: "token", MaxAge: -1},
	})
	if len(sess.Cookies) != 0 {
		t.Fatalf("expected deleted cookie to be removed from session, got %+v", sess.Cookies)
	}
	if err := sess.Save(); err != nil {
		t.Fatalf("save after deletion failed: %v", err)
	}

	sess, err = Load("delete-test")
	if err != nil {
		t.Fatalf("reload after deletion failed: %v", err)
	}
	if len(sess.Cookies) != 0 {
		t.Fatalf("expected deleted cookie to stay removed after reload, got %+v", sess.Cookies)
	}
}

func TestSessionJarDeletionUsesRFCDefaultPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	sess, err := Load("default-path-delete-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jar := sess.Jar()
	login, _ := url.Parse("https://example.com/app/login")
	jar.SetCookies(login, []*http.Cookie{
		{Name: "token", Value: "live"},
	})
	if err := sess.Save(); err != nil {
		t.Fatalf("initial save failed: %v", err)
	}

	sess, err = Load("default-path-delete-test")
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if len(sess.Cookies) != 1 || sess.Cookies[0].Path != "/app" {
		t.Fatalf("expected /app cookie after reload, got %+v", sess.Cookies)
	}

	jar = sess.Jar()
	jar.SetCookies(login, []*http.Cookie{
		{Name: "token", MaxAge: -1},
	})
	if len(sess.Cookies) != 0 {
		t.Fatalf("expected deleted cookie to be removed from session, got %+v", sess.Cookies)
	}
}

func TestCorruptedSessionFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FETCH_INTERNAL_SESSIONS_DIR", dir)

	// Write a corrupted file.
	path := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Load should return the session and a parse error.
	sess, err := Load("corrupt")
	if err == nil {
		t.Fatal("expected error for corrupted session")
	}
	if sess == nil {
		t.Fatal("expected non-nil session even when corrupted")
	}
	if len(sess.Cookies) != 0 {
		t.Fatalf("expected no cookies, got %d", len(sess.Cookies))
	}
}
