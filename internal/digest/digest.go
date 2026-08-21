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
//
// Digest parameters use the HTTP quoted-string grammar. In particular, a
// backslash quotes the following octet and cannot occur as the last octet of a
// quoted value. Parsing is strict so a malformed challenge is not silently
// treated as an ordinary 401 response.
func ParseChallenge(header string) (*Challenge, error) {
	if len(header) < len("Digest ") || !strings.EqualFold(header[:len("Digest ")], "Digest ") {
		return nil, fmt.Errorf("not a digest challenge")
	}

	params, err := parseParams(header[len("Digest "):])
	if err != nil {
		return nil, err
	}
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
	if _, ok := params["qop"]; ok && chal.QOP == "" {
		return nil, fmt.Errorf("malformed digest challenge parameter: empty qop")
	}
	if _, ok := params["algorithm"]; ok && chal.Algorithm == "" {
		return nil, fmt.Errorf("malformed digest challenge parameter: empty algorithm")
	}
	return chal, nil
}

func parseParams(s string) (map[string]string, error) {
	params := make(map[string]string)
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return params, nil
		}

		keyEnd := strings.IndexByte(s, '=')
		if keyEnd < 0 {
			return nil, fmt.Errorf("malformed digest challenge parameter")
		}
		key := strings.TrimSpace(s[:keyEnd])
		if key == "" || !validToken(key) {
			return nil, fmt.Errorf("malformed digest challenge parameter")
		}
		s = strings.TrimLeft(s[keyEnd+1:], " \t")

		var value string
		if strings.HasPrefix(s, "\"") {
			var rest string
			var ok bool
			value, rest, ok = parseQuotedString(s)
			if !ok {
				return nil, fmt.Errorf("malformed digest challenge quoted string")
			}
			s = rest
		} else {
			comma := strings.IndexByte(s, ',')
			if comma < 0 {
				value, s = strings.TrimSpace(s), ""
			} else {
				value, s = strings.TrimSpace(s[:comma]), s[comma:]
			}
			if value == "" {
				return nil, fmt.Errorf("malformed digest challenge parameter")
			}
		}

		params[strings.ToLower(key)] = value
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return params, nil
		}
		if s[0] != ',' {
			return nil, fmt.Errorf("malformed digest challenge parameter")
		}
		s = s[1:]
		if strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("malformed digest challenge parameter")
		}
	}
}

func validToken(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return value != ""
}

// parseQuotedString returns the decoded value and the unconsumed suffix. The
// bool reports whether a closing quote was found.
func parseQuotedString(s string) (value, rest string, ok bool) {
	if len(s) == 0 || s[0] != '"' {
		return "", s, false
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			return b.String(), s[i+1:], true
		case '\\':
			if i+1 >= len(s) || !validQuotedPair(s[i+1]) {
				return "", s, false
			}
			b.WriteByte(s[i+1])
			i++
		default:
			if (s[i] < 0x20 && s[i] != '\t') || s[i] == 0x7f {
				return "", s, false
			}
			b.WriteByte(s[i])
		}
	}
	return "", s, false
}

func validQuotedPair(c byte) bool {
	// RFC 9110 quoted-pair permits HTAB, SP, VCHAR, and obs-text. Reject other
	// controls so malformed wire data cannot become an authorization value.
	return c == '\t' || c == ' ' || (c >= 0x21 && c <= 0x7e) || c >= 0x80
}

// Response builds an Authorization header value for a Digest challenge.
func Response(req *http.Request, chal *Challenge, username, password string) (string, error) {
	if req == nil || req.URL == nil {
		return "", fmt.Errorf("digest request has no URL")
	}
	if chal == nil {
		return "", fmt.Errorf("digest challenge is nil")
	}
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}

	algorithm := strings.ToLower(strings.TrimSpace(chal.Algorithm))
	if algorithm == "" {
		algorithm = "md5"
	}
	hashFunc, err := hashForAlgorithm(algorithm)
	if err != nil {
		return "", err
	}

	qopHasAuth := false
	qop := strings.TrimSpace(chal.QOP)
	if qop != "" {
		for token := range strings.SplitSeq(qop, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "auth") {
				qopHasAuth = true
				break
			}
		}
		if !qopHasAuth {
			return "", fmt.Errorf("unsupported digest qop: %s", chal.QOP)
		}
	}

	var cnonce string
	if strings.HasSuffix(algorithm, "-sess") || qopHasAuth {
		cnonce, err = randomNonce()
		if err != nil {
			return "", fmt.Errorf("generate digest cnonce: %w", err)
		}
	}

	return responseWithCnonce(req, chal, username, password, algorithm, hashFunc, cnonce)
}

// responseWithCnonce contains the deterministic RFC 7616 calculation. It is
// kept separate from secure cnonce generation so the calculation can be
// checked against published vectors without weakening production randomness.
func responseWithCnonce(req *http.Request, chal *Challenge, username, password, algorithm string, hashFunc func() hash.Hash, cnonce string) (string, error) {
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	qopHasAuth := false
	for token := range strings.SplitSeq(chal.QOP, ",") {
		if strings.EqualFold(strings.TrimSpace(token), "auth") {
			qopHasAuth = true
			break
		}
	}

	ha1 := hashDigest(hashFunc, username+":"+chal.Realm+":"+password)
	if strings.HasSuffix(algorithm, "-sess") {
		ha1 = hashDigest(hashFunc, ha1+":"+chal.Nonce+":"+cnonce)
	}

	ha2 := hashDigest(hashFunc, req.Method+":"+uri)
	if qopHasAuth {
		const nc = "00000001"
		response := hashDigest(hashFunc, ha1+":"+chal.Nonce+":"+nc+":"+cnonce+":auth:"+ha2)
		return fmt.Sprintf(
			`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=%s, response="%s", qop=auth, nc=%s, cnonce="%s"`,
			escapeQuotes(username), escapeQuotes(chal.Realm), escapeQuotes(chal.Nonce),
			escapeQuotes(uri), algorithmHeader(algorithm), response, nc, cnonce,
		) + opaqueParam(chal.Opaque), nil
	}

	response := hashDigest(hashFunc, ha1+":"+chal.Nonce+":"+ha2)
	auth := fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=%s, response="%s"`,
		escapeQuotes(username), escapeQuotes(chal.Realm), escapeQuotes(chal.Nonce),
		escapeQuotes(uri), algorithmHeader(algorithm), response,
	)
	if strings.HasSuffix(algorithm, "-sess") {
		auth += fmt.Sprintf(`, cnonce="%s"`, escapeQuotes(cnonce))
	}
	return auth + opaqueParam(chal.Opaque), nil
}

func opaqueParam(opaque string) string {
	if opaque == "" {
		return ""
	}
	return fmt.Sprintf(", opaque=\"%s\"", escapeQuotes(opaque))
}

func hashForAlgorithm(algorithm string) (func() hash.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "md5", "md5-sess":
		return md5.New, nil
	case "sha-256", "sha-256-sess":
		return sha256.New, nil
	case "sha-512-256", "sha-512-256-sess":
		return sha512.New512_256, nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm: %s", strings.ToLower(strings.TrimSpace(algorithm)))
	}
}

func algorithmHeader(algorithm string) string {
	switch strings.ToLower(algorithm) {
	case "md5":
		return "MD5"
	case "md5-sess":
		return "MD5-SESS"
	case "sha-256":
		return "SHA-256"
	case "sha-256-sess":
		return "SHA-256-SESS"
	case "sha-512-256":
		return "SHA-512-256"
	case "sha-512-256-sess":
		return "SHA-512-256-SESS"
	default:
		return algorithm
	}
}

func hashDigest(h func() hash.Hash, s string) string {
	hasher := h()
	_, _ = io.WriteString(hasher, s)
	return hex.EncodeToString(hasher.Sum(nil))
}

func randomNonce() (string, error) {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func escapeQuotes(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}
