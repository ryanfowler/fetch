package session

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ryanfowler/fetch/internal/fileutil"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var validName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

const (
	sessionLockTimeout    = 5 * time.Second
	sessionLockPoll       = 10 * time.Millisecond
	sessionLockStaleAfter = 30 * time.Second
)

// IsValidName returns true if the session name contains only
// alphanumeric characters, hyphens, and underscores.
func IsValidName(name string) bool {
	return validName.MatchString(name)
}

// SessionCookie represents a JSON-serializable cookie.
type SessionCookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain"`
	HostOnly bool      `json:"host_only,omitzero"`
	Path     string    `json:"path,omitzero"`
	Expires  time.Time `json:"expires,omitzero"`
	Secure   bool      `json:"secure,omitzero"`
	HttpOnly bool      `json:"http_only,omitzero"`
	SameSite string    `json:"same_site,omitzero"`
}

// sessionFile is the on-disk JSON format.
type sessionFile struct {
	Cookies []SessionCookie `json:"cookies"`
}

// Session represents a named cookie session.
type Session struct {
	Name    string
	Cookies []SessionCookie
	path    string

	mu          sync.Mutex
	baseCookies []SessionCookie
	corrupt     bool
}

// Load loads a session from disk or creates a new empty session.
// Expired cookies are filtered out on load.
func Load(name string) (*Session, error) {
	return load(name, true)
}

// LoadReadOnly loads a session without creating or modifying its directory.
// It is used by dry-run so presentation can include existing cookies without
// changing session state merely because the configured directory is absent.
func LoadReadOnly(name string) (*Session, error) {
	return load(name, false)
}

func load(name string, createDir bool) (*Session, error) {
	if !IsValidName(name) {
		return nil, fmt.Errorf("invalid session name %q", name)
	}
	dir, err := getSessionsDir(createDir)
	if err != nil {
		return nil, err
	}

	s := &Session{
		Name: name,
		path: filepath.Join(dir, name+".json"),
	}
	cookies, err := readCookies(s.path)
	if err != nil {
		// Return the session so callers can report the corruption without
		// replacing the file accidentally.
		s.corrupt = true
		return s, err
	}
	s.Cookies = cookies
	s.baseCookies = cloneCookies(cookies)
	return s, nil
}

// Save merges this session's changes with the latest on-disk state and then
// atomically commits the result. This prevents concurrent fetch processes from
// losing cookie updates or deletions.
func (s *Session) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.corrupt {
		return fmt.Errorf("cannot save corrupted session %q", s.Name)
	}

	release, err := acquireLock(s.path + ".lock")
	if err != nil {
		return err
	}
	defer release()

	latest, err := readCookies(s.path)
	if err != nil {
		return fmt.Errorf("reload session before save: %w", err)
	}
	merged := mergeCookies(s.baseCookies, s.Cookies, latest)
	data, err := json.MarshalIndent(sessionFile{Cookies: merged}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if err := writeSessionFile(s.path, data); err != nil {
		return err
	}
	s.Cookies = merged
	s.baseCookies = cloneCookies(merged)
	return nil
}

func readCookies(path string) ([]SessionCookie, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var f sessionFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	now := time.Now()
	cookies := make([]SessionCookie, 0, len(f.Cookies))
	for _, c := range f.Cookies {
		if !c.Expires.IsZero() && c.Expires.Before(now) {
			continue
		}
		cookies = append(cookies, c)
	}
	return cookies, nil
}

func writeSessionFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".session-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := fileutil.AtomicReplaceFileNoSymlink(tmpPath, path); err != nil {
		return err
	}
	removeTemp = false
	_ = fileutil.SyncDir(dir)
	return nil
}

func acquireLock(path string) (func(), error) {
	deadline := time.Now().Add(sessionLockTimeout)
	for {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		// A process can die after creating the sentinel and before its
		// deferred cleanup runs. Recover only locks that are well past the
		// normal save duration; an active save keeps the lock fresh enough
		// that it is not mistaken for a crashed owner.
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > sessionLockStaleAfter {
			if removeErr := os.Remove(path); removeErr == nil {
				continue
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for session lock %q", path)
		}
		time.Sleep(sessionLockPoll)
	}
}

type cookieKey struct {
	name, domain, path string
}

func keyForCookie(c SessionCookie) cookieKey {
	return cookieKey{c.Name, normalizeCookieDomain(c.Domain), normalizeCookiePath(c.Path)}
}

func cloneCookies(cookies []SessionCookie) []SessionCookie {
	return append([]SessionCookie(nil), cookies...)
}

func mergeCookies(base, local, latest []SessionCookie) []SessionCookie {
	merged := cloneCookies(latest)
	baseByKey := make(map[cookieKey]SessionCookie, len(base))
	localByKey := make(map[cookieKey]SessionCookie, len(local))
	for _, c := range base {
		baseByKey[keyForCookie(c)] = c
	}
	for _, c := range local {
		localByKey[keyForCookie(c)] = c
	}

	// A cookie absent from the local state was deliberately deleted after the
	// session was loaded. Apply that deletion to the latest state as well.
	for key := range baseByKey {
		if _, ok := localByKey[key]; !ok {
			merged = removeCookieKey(merged, key)
		}
	}
	// Local additions and updates win over a concurrent value for the same
	// cookie. Unchanged local cookies leave newer remote values untouched.
	for _, c := range local {
		key := keyForCookie(c)
		old, existed := baseByKey[key]
		if !existed || old != c {
			merged = upsertCookie(merged, c)
		}
	}
	return merged
}

func removeCookieKey(cookies []SessionCookie, key cookieKey) []SessionCookie {
	out := cookies[:0]
	for _, c := range cookies {
		if keyForCookie(c) != key {
			out = append(out, c)
		}
	}
	return out
}

func upsertCookie(cookies []SessionCookie, cookie SessionCookie) []SessionCookie {
	key := keyForCookie(cookie)
	for i, existing := range cookies {
		if keyForCookie(existing) == key {
			cookies[i] = cookie
			return cookies
		}
	}
	return append(cookies, cookie)
}

// Jar returns an http.CookieJar that persists cookies to this session.
func (s *Session) Jar() http.CookieJar {
	jar := newCookieJar()

	// Pre-populate the jar with saved cookies, grouped by URL.
	byURL := make(map[string][]*http.Cookie)
	s.mu.Lock()
	cookies := cloneCookies(s.Cookies)
	s.mu.Unlock()
	for _, c := range cookies {
		scheme := "http"
		if c.Secure {
			scheme = "https"
		}
		host := c.Domain
		// url.URL requires brackets around an IPv6 literal. The persisted
		// cookie domain intentionally omits them, so add them only while
		// rebuilding the jar.
		if strings.Contains(host, ":") && net.ParseIP(host) != nil {
			host = "[" + host + "]"
		}
		key := fmt.Sprintf("%s://%s%s", scheme, host, c.Path)
		hc := &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Expires:  c.Expires,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
		}
		if !c.HostOnly {
			hc.Domain = c.Domain
		}
		switch c.SameSite {
		case "lax":
			hc.SameSite = http.SameSiteLaxMode
		case "strict":
			hc.SameSite = http.SameSiteStrictMode
		case "none":
			hc.SameSite = http.SameSiteNoneMode
		}
		byURL[key] = append(byURL[key], hc)
	}
	for rawURL, cookies := range byURL {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		jar.SetCookies(u, cookies)
	}

	return &sessionJar{jar: jar, session: s}
}

func newCookieJar() *cookiejar.Jar {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return jar
}

// sessionJar wraps a cookiejar.Jar and records cookies for persistence.
type sessionJar struct {
	jar     *cookiejar.Jar
	session *Session
}

func (j *sessionJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.jar.SetCookies(u, cookies)

	// Record cookies into the session.
	j.session.mu.Lock()
	defer j.session.mu.Unlock()
	now := time.Now()
	for _, c := range cookies {
		sc, remove, ok := sessionCookieFromSetCookie(u, c, now)
		if !ok {
			continue
		}

		if remove {
			j.session.removeCookie(sc.Name, sc.Domain, sc.Path)
			continue
		}

		// Update existing cookie or append new one.
		found := false
		for i, existing := range j.session.Cookies {
			if cookieKeyMatches(existing, sc.Name, sc.Domain, sc.Path) {
				j.session.Cookies[i] = sc
				found = true
				break
			}
		}
		if !found {
			j.session.Cookies = append(j.session.Cookies, sc)
		}
	}
}

func (j *sessionJar) Cookies(u *url.URL) []*http.Cookie {
	return j.jar.Cookies(u)
}

func sessionCookieFromSetCookie(u *url.URL, c *http.Cookie, now time.Time) (SessionCookie, bool, bool) {
	if u.Scheme != "http" && u.Scheme != "https" {
		return SessionCookie{}, false, false
	}
	host, ok := canonicalCookieHost(u.Host)
	if !ok {
		return SessionCookie{}, false, false
	}
	domain, hostOnly, ok := cookieDomainAndType(host, c.Domain)
	if !ok {
		return SessionCookie{}, false, false
	}

	sc := SessionCookie{
		Name:     c.Name,
		Value:    c.Value,
		Domain:   domain,
		HostOnly: hostOnly,
		Path:     cookiePath(u.Path, c.Path),
		Expires:  cookieExpires(c, now),
		Secure:   c.Secure,
		HttpOnly: c.HttpOnly,
	}
	switch c.SameSite {
	case http.SameSiteLaxMode:
		sc.SameSite = "lax"
	case http.SameSiteStrictMode:
		sc.SameSite = "strict"
	case http.SameSiteNoneMode:
		sc.SameSite = "none"
	}

	return sc, isDeletionCookie(c, now), true
}

func canonicalCookieHost(host string) (string, bool) {
	if hasPort(host) {
		var err error
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return "", false
		}
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	host = strings.TrimSuffix(host, ".")
	if lower, ok := asciiLower(host); ok {
		return lower, true
	}
	encoded, err := idna.ToASCII(host)
	if err != nil {
		return "", false
	}
	lower, ok := asciiLower(encoded)
	return lower, ok
}

func hasPort(host string) bool {
	colons := strings.Count(host, ":")
	if colons == 0 {
		return false
	}
	if colons == 1 {
		return true
	}
	return host[0] == '[' && strings.Contains(host, "]:")
}

func cookieDomainAndType(host, domain string) (string, bool, bool) {
	if domain == "" {
		return host, true, true
	}

	if isIP(host) {
		if host != domain {
			return "", false, false
		}
		return host, true, true
	}

	domain = strings.TrimPrefix(domain, ".")
	if len(domain) == 0 || domain[0] == '.' {
		return "", false, false
	}

	var ok bool
	domain, ok = asciiLower(domain)
	if !ok {
		return "", false, false
	}
	if domain[len(domain)-1] == '.' {
		return "", false, false
	}

	if ps := publicsuffix.List.PublicSuffix(domain); ps != "" && !hasDotSuffix(domain, ps) {
		if host == domain {
			return host, true, true
		}
		return "", false, false
	}

	if host != domain && !hasDotSuffix(host, domain) {
		return "", false, false
	}

	return domain, false, true
}

func cookiePath(requestPath, cookiePath string) string {
	if cookiePath == "" || cookiePath[0] != '/' {
		return defaultCookiePath(requestPath)
	}
	return cookiePath
}

func asciiLower(s string) (string, bool) {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x80 {
			return "", false
		}
		if 'A' <= c && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + ('a' - 'A')
		}
	}
	if b != nil {
		return string(b), true
	}
	return s, true
}

func hasDotSuffix(s, suffix string) bool {
	return len(s) > len(suffix) && s[len(s)-len(suffix)-1] == '.' && s[len(s)-len(suffix):] == suffix
}

func isIP(host string) bool {
	if strings.ContainsAny(host, ":%") {
		return true
	}
	return net.ParseIP(host) != nil
}

func (s *Session) removeCookie(name, domain, path string) {
	filtered := s.Cookies[:0]
	for _, existing := range s.Cookies {
		if cookieKeyMatches(existing, name, domain, path) {
			continue
		}
		filtered = append(filtered, existing)
	}
	s.Cookies = filtered
}

func cookieKeyMatches(c SessionCookie, name, domain, path string) bool {
	return c.Name == name &&
		normalizeCookieDomain(c.Domain) == domain &&
		normalizeCookiePath(c.Path) == path
}

func normalizeCookieDomain(domain string) string {
	return strings.TrimPrefix(strings.ToLower(domain), ".")
}

func normalizeCookiePath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func defaultCookiePath(path string) string {
	if path == "" || path[0] != '/' {
		return "/"
	}
	i := strings.LastIndex(path, "/")
	if i == 0 {
		return "/"
	}
	return path[:i]
}

func isDeletionCookie(c *http.Cookie, now time.Time) bool {
	if c.MaxAge != 0 {
		return c.MaxAge < 0
	}
	return !c.Expires.IsZero() && !c.Expires.After(now)
}

func cookieExpires(c *http.Cookie, now time.Time) time.Time {
	if c.MaxAge > 0 {
		return now.Add(time.Duration(c.MaxAge) * time.Second)
	}
	return c.Expires
}

func getSessionsDir(create bool) (string, error) {
	// Allow override for testing.
	if dir := os.Getenv("FETCH_INTERNAL_SESSIONS_DIR"); dir != "" {
		if create {
			if err := os.MkdirAll(dir, 0700); err != nil {
				return "", err
			}
			if err := os.Chmod(dir, 0700); err != nil {
				return "", err
			}
		}
		return dir, nil
	}

	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, "fetch", "sessions")
	if create {
		if err := os.MkdirAll(path, 0700); err != nil {
			return "", err
		}
		if err := os.Chmod(path, 0700); err != nil {
			return "", err
		}
	}
	return path, nil
}
