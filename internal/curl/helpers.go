package curl

import (
	"fmt"
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

// addCookie adds the inline cookies of one -b/--cookie value. Like curl, it
// joins the values of repeated options with "; ", so each value is sent.
func (r *Result) addCookie(v string) error {
	if err := validateCookieValue(v); err != nil {
		return err
	}
	if r.Cookie == "" {
		r.Cookie = v
	} else {
		r.Cookie += "; " + v
	}
	return nil
}

// curlProtocols are the protocol names that curl's --proto accepts.
var curlProtocols = map[string]struct{}{
	"dict": {}, "file": {}, "ftp": {}, "ftps": {}, "gopher": {}, "gophers": {},
	"http": {}, "https": {}, "imap": {}, "imaps": {}, "ipfs": {}, "ipns": {},
	"ldap": {}, "ldaps": {}, "mqtt": {}, "mqtts": {}, "pop3": {}, "pop3s": {},
	"rtsp": {}, "scp": {}, "sftp": {}, "smtp": {}, "smtps": {}, "telnet": {},
	"tftp": {}, "ws": {}, "wss": {},
}

// AllowedProtocols is the result of a curl --proto value, for the protocols
// that fetch supports.
type AllowedProtocols struct {
	allowed map[string]bool
}

// fetchProtocols are the protocols in AllowedProtocols.
var fetchProtocols = []string{"http", "https", "ws", "wss"}

// Allows reports whether the URL scheme is allowed.
func (p AllowedProtocols) Allows(scheme string) bool {
	return p.allowed[strings.ToLower(scheme)]
}

// ParseAllowedProto parses a curl --proto value. As in curl, the
// comma-separated items are evaluated left to right. Each item is a protocol
// name or "all", with an optional modifier: "+" permits it (the default),
// "-" denies it, and "=" denies every protocol and then permits it. Every
// protocol is allowed before the first item. For example, "=https" and
// "-all,https" allow only HTTPS. As in curl, an empty or unknown protocol
// name is an error.
func ParseAllowedProto(value string) (AllowedProtocols, error) {
	allowed := make(map[string]bool, len(fetchProtocols))
	setAll := func(permit bool) {
		for _, name := range fetchProtocols {
			allowed[name] = permit
		}
	}
	setAll(true)
	for item := range strings.SplitSeq(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		modifier := byte('+')
		if strings.IndexByte("+-=", item[0]) >= 0 {
			modifier, item = item[0], item[1:]
		}
		name := strings.ToLower(item)
		if _, known := curlProtocols[name]; !known && name != "all" {
			return AllowedProtocols{}, fmt.Errorf("--proto %q: unrecognized protocol %q", value, item)
		}
		permit := modifier != '-'
		if modifier == '=' {
			setAll(false)
		}
		if name == "all" {
			setAll(permit)
		} else if _, ok := allowed[name]; ok {
			allowed[name] = permit
		}
	}
	return AllowedProtocols{allowed: allowed}, nil
}
