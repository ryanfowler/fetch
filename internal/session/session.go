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
	"time"

	"github.com/ryanfowler/fetch/internal/fileutil"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var validName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

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
}

// Load loads a session from disk or creates a new empty session.
// Expired cookies are filtered out on load.
func Load(name string) (*Session, error) {
	dir, err := getSessionsDir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, name+".json")
	s := &Session{
		Name: name,
		path: path,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}

	var f sessionFile
	if err := json.Unmarshal(data, &f); err != nil {
		return s, err
	}

	// Filter expired cookies.
	now := time.Now()
	cookies := make([]SessionCookie, 0, len(f.Cookies))
	for _, c := range f.Cookies {
		if !c.Expires.IsZero() && c.Expires.Before(now) {
			continue
		}
		cookies = append(cookies, c)
	}
	s.Cookies = cookies

	return s, nil
}

// Save atomically writes the session to disk.
func (s *Session) Save() error {
	f := sessionFile{Cookies: s.Cookies}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	// Atomic write: write to temp file, then rename.
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".session-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := fileutil.AtomicReplaceFile(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// Jar returns an http.CookieJar that persists cookies to this session.
func (s *Session) Jar() http.CookieJar {
	jar := newCookieJar()

	// Pre-populate the jar with saved cookies, grouped by URL.
	byURL := make(map[string][]*http.Cookie)
	for _, c := range s.Cookies {
		scheme := "http"
		if c.Secure {
			scheme = "https"
		}
		key := fmt.Sprintf("%s://%s%s", scheme, c.Domain, c.Path)
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

func getSessionsDir() (string, error) {
	// Allow override for testing.
	if dir := os.Getenv("FETCH_INTERNAL_SESSIONS_DIR"); dir != "" {
		err := os.MkdirAll(dir, 0700)
		if err != nil {
			return "", err
		}
		return dir, nil
	}

	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, "fetch", "sessions")
	err = os.MkdirAll(path, 0700)
	if err != nil {
		return "", err
	}

	return path, nil
}
