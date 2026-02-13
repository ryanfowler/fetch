package curl

import (
	"fmt"
	"net/url"
	"strings"
)

func parseHeader(s string) (header, error) {
	name, value, ok := strings.Cut(s, ":")
	if !ok {
		return header{}, fmt.Errorf("invalid header: %q", s)
	}
	return header{
		Name:  strings.TrimSpace(name),
		Value: strings.TrimSpace(value),
	}, nil
}

func parseFormField(s string) formField {
	name, value, _ := strings.Cut(s, "=")
	return formField{
		Name:  name,
		Value: value,
	}
}

// validateCookieValue checks if the -b/--cookie value looks like a cookie
// file path rather than an inline cookie string. In curl, if the value
// contains '=' it is treated as a cookie string (e.g. "name=value"); otherwise
// it is interpreted as a cookie jar file path (e.g. "cookies.txt"). Cookie jar
// files are not supported by this parser.
func validateCookieValue(v string) error {
	if !strings.Contains(v, "=") {
		return fmt.Errorf("cookie jar files are not supported; -b/--cookie value %q looks like a file path (use -b 'name=value' for inline cookies)", v)
	}
	return nil
}

// urlEncodeValue processes a --data-urlencode value. For inline forms
// (content, =content, name=content) it URL-encodes immediately. For file
// forms (@filename, name@filename) it returns the raw value and sets a flag
// so that the caller can read the file and URL-encode its contents.
func urlEncodeValue(s string) (DataValue, error) {
	// "@filename" - read file, URL-encode contents.
	if strings.HasPrefix(s, "@") {
		return DataValue{Value: s, IsURLEncode: true}, nil
	}

	// "name@filename" - read file, URL-encode contents, prepend "name=".
	// We check for '@' before '=' to distinguish from "name=content".
	eqIdx := strings.Index(s, "=")
	atIdx := strings.Index(s, "@")
	if atIdx > 0 && (eqIdx < 0 || atIdx < eqIdx) {
		return DataValue{Value: s, IsURLEncode: true}, nil
	}

	// Inline forms: URL-encode immediately.
	if name, content, ok := strings.Cut(s, "="); ok {
		if name == "" {
			return DataValue{Value: url.QueryEscape(content)}, nil
		}
		return DataValue{Value: name + "=" + url.QueryEscape(content)}, nil
	}
	return DataValue{Value: url.QueryEscape(s)}, nil
}

// ParseAllowedProto parses a curl --proto value and returns which protocols
// are allowed. Curl syntax: "=https" means only HTTPS; "http,https" or
// "+http" adds to defaults; "-http" removes from defaults.
// Returns (allowHTTP, allowHTTPS).
func ParseAllowedProto(value string) (bool, bool) {
	if value == "" {
		return true, true
	}

	// "=" prefix means "only these protocols".
	exclusive := strings.HasPrefix(value, "=")
	if exclusive {
		value = value[1:]
	}

	// Start with defaults (both allowed) unless exclusive mode.
	allowHTTP := !exclusive
	allowHTTPS := !exclusive

	for proto := range strings.SplitSeq(value, ",") {
		proto = strings.TrimSpace(proto)
		if proto == "" {
			continue
		}

		switch {
		case proto == "http" || proto == "+http":
			allowHTTP = true
		case proto == "https" || proto == "+https":
			allowHTTPS = true
		case proto == "-http":
			allowHTTP = false
		case proto == "-https":
			allowHTTPS = false
		}
	}

	return allowHTTP, allowHTTPS
}
