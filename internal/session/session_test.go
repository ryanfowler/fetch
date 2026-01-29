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
