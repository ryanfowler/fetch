package digest

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
)

// Challenge represents a parsed Digest authentication challenge.
type Challenge struct {
	Realm     string
	Nonce     string
	Opaque    string
	QOP       string
	Algorithm string
	Stale     string
}

// ParseChallenge parses a WWW-Authenticate header value for Digest auth.
func ParseChallenge(header string) (*Challenge, error) {
	if !strings.HasPrefix(strings.ToUpper(header), "DIGEST ") {
		return nil, fmt.Errorf("not a digest challenge")
	}

	params := parseParams(header[strings.IndexByte(header, ' ')+1:])
	chal := &Challenge{
		Realm:     params["realm"],
		Nonce:     params["nonce"],
		Opaque:    params["opaque"],
		QOP:       params["qop"],
		Algorithm: params["algorithm"],
		Stale:     params["stale"],
	}
	if chal.Realm == "" || chal.Nonce == "" {
		return nil, fmt.Errorf("missing required digest challenge parameter")
	}
	return chal, nil
}

// parseParams parses comma-separated key=value pairs from a header value.
// Values may be quoted or unquoted.
func parseParams(s string) map[string]string {
	params := make(map[string]string)
	for len(s) > 0 {
		s = strings.TrimSpace(s)
		if s == "" {
			break
		}
		key, rest, ok := strings.Cut(s, "=")
		if !ok {
			break
		}
		key = strings.TrimSpace(key)
		rest = strings.TrimSpace(rest)

		var value string
		if len(rest) > 0 && rest[0] == '"' {
			// Quoted string.
			value, rest = parseQuotedString(rest)
		} else {
			// Unquoted value, read until comma.
			var val string
			val, rest, _ = strings.Cut(rest, ",")
			value = strings.TrimSpace(val)
		}
		params[strings.ToLower(key)] = value
		if len(rest) > 0 && rest[0] == ',' {
			rest = rest[1:]
		}
		s = rest
	}
	return params
}

func parseQuotedString(s string) (string, string) {
	if len(s) == 0 || s[0] != '"' {
		return "", s
	}
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		if c == '"' {
			i++
			break
		}
		if c == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i += 2
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), s[i:]
}

// Response builds an Authorization header value for a Digest challenge.
func Response(req *http.Request, chal *Challenge, username, password string) (string, error) {
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}

	algorithm := strings.ToLower(chal.Algorithm)
	if algorithm == "" {
		algorithm = "md5"
	}

	hashFunc, err := hashForAlgorithm(algorithm)
	if err != nil {
		return "", err
	}

	qop := strings.ToLower(chal.QOP)
	qopHasAuth := false
	for _, token := range strings.Split(qop, ",") {
		if strings.TrimSpace(token) == "auth" {
			qopHasAuth = true
			break
		}
	}
	if qop != "" && !qopHasAuth {
		return "", fmt.Errorf("unsupported digest qop: %s", chal.QOP)
	}

	var cnonce string
	if isSessAlgorithm(algorithm) || qopHasAuth {
		cnonce = randomNonce()
	}

	ha1 := hashDigest(hashFunc, username+":"+chal.Realm+":"+password)
	if isSessAlgorithm(algorithm) {
		ha1 = hashDigest(hashFunc, ha1+":"+chal.Nonce+":"+cnonce)
	}

	ha2 := hashDigest(hashFunc, req.Method+":"+uri)

	var response string
	if qopHasAuth {
		nc := "00000001"
		response = hashDigest(hashFunc, ha1+":"+chal.Nonce+":"+nc+":"+cnonce+":auth:"+ha2)
		return fmt.Sprintf(
			`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=%s, response="%s", qop=auth, nc=%s, cnonce="%s"`,
			escapeQuotes(username), escapeQuotes(chal.Realm), escapeQuotes(chal.Nonce),
			escapeQuotes(uri), strings.ToUpper(algorithm), response, nc, cnonce,
		) + opaqueParam(chal.Opaque), nil
	}

	response = hashDigest(hashFunc, ha1+":"+chal.Nonce+":"+ha2)
	return fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=%s, response="%s"`,
		escapeQuotes(username), escapeQuotes(chal.Realm), escapeQuotes(chal.Nonce),
		escapeQuotes(uri), strings.ToUpper(algorithm), response,
	) + opaqueParam(chal.Opaque), nil
}

func opaqueParam(opaque string) string {
	if opaque == "" {
		return ""
	}
	return fmt.Sprintf(", opaque=\"%s\"", escapeQuotes(opaque))
}

func hashForAlgorithm(algorithm string) (func() hash.Hash, error) {
	switch algorithm {
	case "md5", "md5-sess":
		return md5.New, nil
	case "sha-256", "sha-256-sess":
		return sha256.New, nil
	case "sha-512-256", "sha-512-256-sess":
		return sha512.New512_256, nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm: %s", algorithm)
	}
}

func isSessAlgorithm(algorithm string) bool {
	return strings.HasSuffix(algorithm, "-sess")
}

func hashDigest(h func() hash.Hash, s string) string {
	hasher := h()
	hasher.Write([]byte(s))
	return hex.EncodeToString(hasher.Sum(nil))
}

func randomNonce() string {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// Fallback: this should never happen in practice.
		for i := range b {
			b[i] = byte(i)
		}
	}
	return hex.EncodeToString(b)
}

func escapeQuotes(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}
