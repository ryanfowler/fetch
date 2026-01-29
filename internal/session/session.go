package session

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
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

	return os.Rename(tmpPath, s.path)
}

// Jar returns an http.CookieJar that persists cookies to this session.
func (s *Session) Jar() http.CookieJar {
	jar, _ := cookiejar.New(nil)

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
			Domain:   c.Domain,
			Path:     c.Path,
			Expires:  c.Expires,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
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

// sessionJar wraps a cookiejar.Jar and records cookies for persistence.
type sessionJar struct {
	jar     *cookiejar.Jar
	session *Session
}

func (j *sessionJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.jar.SetCookies(u, cookies)

	// Record cookies into the session.
	for _, c := range cookies {
		sc := SessionCookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Expires:  c.Expires,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
		}
		if sc.Domain == "" {
			sc.Domain = u.Hostname()
		}
		if sc.Path == "" {
			sc.Path = "/"
		}
		switch c.SameSite {
		case http.SameSiteLaxMode:
			sc.SameSite = "lax"
		case http.SameSiteStrictMode:
			sc.SameSite = "strict"
		case http.SameSiteNoneMode:
			sc.SameSite = "none"
		}

		// Update existing cookie or append new one.
		found := false
		for i, existing := range j.session.Cookies {
			if existing.Name == sc.Name && existing.Domain == sc.Domain && existing.Path == sc.Path {
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

func getSessionsDir() (string, error) {
	// Allow override for testing.
	if dir := os.Getenv("FETCH_INTERNAL_SESSIONS_DIR"); dir != "" {
		err := os.MkdirAll(dir, 0755)
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
	err = os.MkdirAll(path, 0755)
	if err != nil {
		return "", err
	}

	return path, nil
}
