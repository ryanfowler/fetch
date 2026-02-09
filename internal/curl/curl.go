package curl

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type header struct {
	Name  string
	Value string
}

type formField struct {
	Name  string
	Value string
}

// DataValue represents a single data value with flags indicating how
// the value should be processed.
type DataValue struct {
	Value       string
	IsRaw       bool // No @file expansion.
	IsURLEncode bool // URL-encode the value (or file contents for @file/name@file forms).
}

// Result is the intermediate representation of a parsed curl command.
type Result struct {
	URL              string
	Method           string
	Headers          []header
	DataValues       []DataValue
	BasicAuth        string
	AWSSigv4         string
	Bearer           string
	FormFields       []formField
	UploadFile       string
	Head             bool
	Insecure         bool
	Output           string
	RemoteName       bool
	RemoteHeaderName bool
	FollowRedirects  bool
	MaxRedirects     int
	Timeout          float64
	ConnectTimeout   float64
	Proxy            string
	DoHURL           string
	HTTPVersion      string
	TLSVersion       string
	CACert           string
	Cert             string
	Key              string
	UnixSocket       string
	Ranges           []string
	Retry            int
	RetryDelay       float64
	GetFlag          bool
	Verbose          int
	Silent           bool
	UserAgent        string
	Referer          string
	Cookie           string
	HasContentType   bool
	HasAccept        bool
	AllowedProto     string // raw --proto value, e.g. "=https" or "http,https"
}

// Parse parses a curl command string and returns a Result.
func Parse(command string) (*Result, error) {
	tokens, err := tokenize(command)
	if err != nil {
		return nil, err
	}

	// Strip leading "curl" word if present.
	if len(tokens) > 0 && tokens[0] == "curl" {
		tokens = tokens[1:]
	}

	r := &Result{}
	if err := parseTokens(r, tokens); err != nil {
		return nil, err
	}

	// Post-processing.
	if err := postProcess(r); err != nil {
		return nil, err
	}

	return r, nil
}

func postProcess(r *Result) error {
	// -G flag: move data to query string.
	if r.GetFlag && len(r.DataValues) > 0 {
		parts := make([]string, len(r.DataValues))
		for i, dv := range r.DataValues {
			parts[i] = dv.Value
		}
		data := strings.Join(parts, "&")
		if r.URL != "" {
			sep := "?"
			if strings.Contains(r.URL, "?") {
				sep = "&"
			}
			r.URL = r.URL + sep + data
		}
		r.DataValues = nil
		if r.Method == "" {
			r.Method = "GET"
		}
	}

	// Reject conflicting body sources.
	if len(r.DataValues) > 0 && r.UploadFile != "" {
		return fmt.Errorf("cannot use both data flags and --upload-file/-T")
	}

	// Infer method.
	if r.Method == "" {
		if r.Head {
			r.Method = "HEAD"
		} else if len(r.DataValues) > 0 || len(r.FormFields) > 0 {
			r.Method = "POST"
		} else if r.UploadFile != "" {
			r.Method = "PUT"
		}
	}

	// Validate URL is present.
	if r.URL == "" {
		return fmt.Errorf("no URL provided in curl command")
	}

	return nil
}

func parseTokens(r *Result, tokens []string) error {
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]

		// Positional argument (URL).
		if !strings.HasPrefix(tok, "-") {
			if r.URL != "" {
				return fmt.Errorf("unexpected argument: %q", tok)
			}
			r.URL = tok
			continue
		}

		// End-of-options marker: treat remaining tokens as positional.
		if tok == "--" {
			for _, rest := range tokens[i+1:] {
				if r.URL != "" {
					return fmt.Errorf("unexpected argument: %q", rest)
				}
				r.URL = rest
			}
			return nil
		}

		// Long flag.
		if strings.HasPrefix(tok, "--") {
			name := tok[2:]

			// Handle --flag=value syntax.
			var value string
			var hasValue bool
			if idx := strings.Index(name, "="); idx >= 0 {
				value = name[idx+1:]
				name = name[:idx]
				hasValue = true
			}

			consumed, err := parseLongFlag(r, name, value, hasValue, tokens[i+1:])
			if err != nil {
				return err
			}
			i += consumed
			continue
		}

		// Short flag(s).
		consumed, err := parseShortFlags(r, tok[1:], tokens[i+1:])
		if err != nil {
			return err
		}
		i += consumed
	}
	return nil
}

func nextArg(args []string) (string, int, error) {
	if len(args) == 0 {
		return "", 0, fmt.Errorf("missing argument")
	}
	return args[0], 1, nil
}

func parseLongFlag(r *Result, name, value string, hasValue bool, rest []string) (int, error) {
	consumeArg := func() (string, int, error) {
		if hasValue {
			return value, 0, nil
		}
		return nextArg(rest)
	}

	switch name {
	// Request basics.
	case "request":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--request requires an argument")
		}
		r.Method = v
		return n, nil
	case "header":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--header requires an argument")
		}
		h, err := parseHeader(v)
		if err != nil {
			return 0, err
		}
		r.Headers = append(r.Headers, h)
		if strings.EqualFold(h.Name, "content-type") {
			r.HasContentType = true
		}
		if strings.EqualFold(h.Name, "accept") {
			r.HasAccept = true
		}
		return n, nil
	case "url":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--url requires an argument")
		}
		if r.URL != "" {
			return 0, fmt.Errorf("unexpected argument: %q", v)
		}
		r.URL = v
		return n, nil
	case "get":
		r.GetFlag = true
		return 0, nil
	case "head":
		r.Head = true
		return 0, nil

	// Request body.
	case "data", "data-ascii", "data-binary":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--%s requires an argument", name)
		}
		r.DataValues = append(r.DataValues, DataValue{Value: v})
		return n, nil
	case "data-raw":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--data-raw requires an argument")
		}
		r.DataValues = append(r.DataValues, DataValue{Value: v, IsRaw: true})
		return n, nil
	case "data-urlencode":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--data-urlencode requires an argument")
		}
		dv, err := urlEncodeValue(v)
		if err != nil {
			return 0, err
		}
		r.DataValues = append(r.DataValues, dv)
		return n, nil
	case "json":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--json requires an argument")
		}
		r.DataValues = append(r.DataValues, DataValue{Value: v})
		// --json implies Content-Type: application/json and Accept: application/json.
		if !r.HasContentType {
			r.Headers = append(r.Headers, header{Name: "Content-Type", Value: "application/json"})
			r.HasContentType = true
		}
		if !r.HasAccept {
			r.Headers = append(r.Headers, header{Name: "Accept", Value: "application/json"})
			r.HasAccept = true
		}
		return n, nil
	case "form":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--form requires an argument")
		}
		r.FormFields = append(r.FormFields, parseFormField(v))
		return n, nil
	case "upload-file":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--upload-file requires an argument")
		}
		r.UploadFile = v
		return n, nil

	// Authentication.
	case "user":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--user requires an argument")
		}
		r.BasicAuth = v
		return n, nil
	case "aws-sigv4":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--aws-sigv4 requires an argument")
		}
		r.AWSSigv4 = v
		return n, nil
	case "oauth2-bearer":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--oauth2-bearer requires an argument")
		}
		r.Bearer = v
		return n, nil

	// TLS / Security.
	case "insecure":
		r.Insecure = true
		return 0, nil
	case "cacert":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--cacert requires an argument")
		}
		r.CACert = v
		return n, nil
	case "cert":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--cert requires an argument")
		}
		r.Cert = v
		return n, nil
	case "key":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--key requires an argument")
		}
		r.Key = v
		return n, nil
	case "tlsv1":
		r.TLSVersion = "1.0"
		return 0, nil
	case "tlsv1.0":
		r.TLSVersion = "1.0"
		return 0, nil
	case "tlsv1.1":
		r.TLSVersion = "1.1"
		return 0, nil
	case "tlsv1.2":
		r.TLSVersion = "1.2"
		return 0, nil
	case "tlsv1.3":
		r.TLSVersion = "1.3"
		return 0, nil

	// Output.
	case "output":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--output requires an argument")
		}
		r.Output = v
		return n, nil
	case "remote-name":
		r.RemoteName = true
		return 0, nil
	case "remote-header-name":
		r.RemoteHeaderName = true
		return 0, nil

	// Connection / Network.
	case "location":
		r.FollowRedirects = true
		return 0, nil
	case "max-redirs":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--max-redirs requires an argument")
		}
		num, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("invalid --max-redirs value: %s", v)
		}
		r.MaxRedirects = num
		return n, nil
	case "max-time":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--max-time requires an argument")
		}
		secs, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid --max-time value: %s", v)
		}
		r.Timeout = secs
		return n, nil
	case "connect-timeout":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--connect-timeout requires an argument")
		}
		secs, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid --connect-timeout value: %s", v)
		}
		r.ConnectTimeout = secs
		return n, nil
	case "proxy":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--proxy requires an argument")
		}
		r.Proxy = v
		return n, nil
	case "unix-socket":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--unix-socket requires an argument")
		}
		r.UnixSocket = v
		return n, nil
	case "doh-url":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--doh-url requires an argument")
		}
		r.DoHURL = v
		return n, nil
	case "retry":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--retry requires an argument")
		}
		num, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("invalid --retry value: %s", v)
		}
		r.Retry = num
		return n, nil
	case "retry-delay":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--retry-delay requires an argument")
		}
		secs, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid --retry-delay value: %s", v)
		}
		r.RetryDelay = secs
		return n, nil
	case "range":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--range requires an argument")
		}
		r.Ranges = append(r.Ranges, v)
		return n, nil

	// HTTP version.
	case "http1.0":
		r.HTTPVersion = "1.0"
		return 0, nil
	case "http1.1":
		r.HTTPVersion = "1.1"
		return 0, nil
	case "http2":
		r.HTTPVersion = "2"
		return 0, nil
	case "http3":
		r.HTTPVersion = "3"
		return 0, nil

	// Convenience headers.
	case "user-agent":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--user-agent requires an argument")
		}
		r.UserAgent = v
		return n, nil
	case "referer":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--referer requires an argument")
		}
		r.Referer = v
		return n, nil
	case "cookie":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--cookie requires an argument")
		}
		if err := validateCookieValue(v); err != nil {
			return 0, err
		}
		r.Cookie = v
		return n, nil

	// Verbosity.
	case "verbose":
		r.Verbose++
		return 0, nil
	case "silent":
		r.Silent = true
		return 0, nil

	// Behavior — no-ops or mapped to fetch defaults.
	case "fail", "fail-with-body":
		return 0, nil
	case "show-error", "compressed", "no-buffer", "no-keepalive",
		"progress-bar", "no-progress-meter", "netrc":
		return 0, nil

	// Protocol restriction.
	case "proto":
		v, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--proto requires an argument")
		}
		r.AllowedProto = v
		return n, nil

	// No-ops that take an argument.
	case "proto-default", "proto-redir":
		_, n, err := consumeArg()
		if err != nil {
			return 0, fmt.Errorf("--%s requires an argument", name)
		}
		return n, nil

	default:
		return 0, fmt.Errorf("unsupported curl flag '--%s'", name)
	}
}

func parseShortFlags(r *Result, flags string, rest []string) (int, error) {
	total := 0
	for i := 0; i < len(flags); i++ {
		c := flags[i]
		remaining := flags[i+1:]

		consumeArg := func() (string, int, error) {
			if len(remaining) > 0 {
				v := remaining
				i = len(flags) // skip rest of short flags
				return v, 0, nil
			}
			return nextArg(rest[total:])
		}

		switch c {
		case 'X':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-X requires an argument")
			}
			r.Method = v
			total += n
		case 'H':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-H requires an argument")
			}
			h, err := parseHeader(v)
			if err != nil {
				return 0, err
			}
			r.Headers = append(r.Headers, h)
			if strings.EqualFold(h.Name, "content-type") {
				r.HasContentType = true
			}
			if strings.EqualFold(h.Name, "accept") {
				r.HasAccept = true
			}
			total += n
		case 'd':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-d requires an argument")
			}
			r.DataValues = append(r.DataValues, DataValue{Value: v})
			total += n
		case 'F':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-F requires an argument")
			}
			r.FormFields = append(r.FormFields, parseFormField(v))
			total += n
		case 'T':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-T requires an argument")
			}
			r.UploadFile = v
			total += n
		case 'u':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-u requires an argument")
			}
			r.BasicAuth = v
			total += n
		case 'E':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-E requires an argument")
			}
			r.Cert = v
			total += n
		case 'o':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-o requires an argument")
			}
			r.Output = v
			total += n
		case 'x':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-x requires an argument")
			}
			r.Proxy = v
			total += n
		case 'm':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-m requires an argument")
			}
			secs, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid -m value: %s", v)
			}
			r.Timeout = secs
			total += n
		case 'r':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-r requires an argument")
			}
			r.Ranges = append(r.Ranges, v)
			total += n
		case 'A':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-A requires an argument")
			}
			r.UserAgent = v
			total += n
		case 'e':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-e requires an argument")
			}
			r.Referer = v
			total += n
		case 'b':
			v, n, err := consumeArg()
			if err != nil {
				return 0, fmt.Errorf("-b requires an argument")
			}
			if err := validateCookieValue(v); err != nil {
				return 0, err
			}
			r.Cookie = v
			total += n
		case 'I':
			r.Head = true
		case 'k':
			r.Insecure = true
		case 'O':
			r.RemoteName = true
		case 'J':
			r.RemoteHeaderName = true
		case 'L':
			r.FollowRedirects = true
		case 'G':
			r.GetFlag = true
		case 'v':
			r.Verbose++
		case 's':
			r.Silent = true
		case 'S', 'N', 'n', 'f':
			// No-ops.
		case '#':
			// No-op: --progress-bar.
		case '0':
			r.HTTPVersion = "1.0"
		default:
			return 0, fmt.Errorf("unsupported curl flag '-%c'", c)
		}
	}
	return total, nil
}

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

// tokenize splits a shell command string into tokens, handling single quotes,
// double quotes, backslash escaping, and line continuations.
func tokenize(s string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	hasContent := false

	i := 0
	for i < len(s) {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			if hasContent {
				tokens = append(tokens, current.String())
				current.Reset()
				hasContent = false
			}
			i++

		case '\'':
			// Single-quoted string: everything is literal until closing quote.
			i++
			for i < len(s) && s[i] != '\'' {
				current.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated single quote")
			}
			i++ // skip closing quote
			hasContent = true

		case '"':
			// Double-quoted string: backslash escapes for ", \, $, `
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					next := s[i+1]
					switch next {
					case '"', '\\', '$', '`':
						current.WriteByte(next)
						i += 2
						continue
					}
				}
				current.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated double quote")
			}
			i++ // skip closing quote
			hasContent = true

		case '\\':
			if i+1 < len(s) {
				next := s[i+1]
				if next == '\n' {
					// Line continuation: skip backslash and newline.
					i += 2
				} else {
					// Escape next character.
					current.WriteByte(next)
					i += 2
					hasContent = true
				}
			} else {
				// Trailing backslash.
				current.WriteByte(c)
				i++
				hasContent = true
			}

		default:
			current.WriteByte(c)
			i++
			hasContent = true
		}
	}

	if hasContent {
		tokens = append(tokens, current.String())
	}

	return tokens, nil
}
