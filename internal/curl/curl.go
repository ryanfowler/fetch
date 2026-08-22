package curl

import (
	"fmt"
	"math"
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
	URL               string
	Method            string
	Headers           []header
	DataValues        []DataValue
	BasicAuth         string
	DigestAuth        bool
	AWSSigv4          string
	Bearer            string
	FormFields        []formField
	UploadFile        string
	Head              bool
	Insecure          bool
	ECH               string
	Output            string
	RemoteName        bool
	RemoteHeaderName  bool
	FollowRedirects   bool
	MaxRedirects      int
	MaxRedirectsSet   bool
	Timeout           float64
	TimeoutSet        bool
	ConnectTimeout    float64
	ConnectTimeoutSet bool
	Proxy             string
	DoHURL            string
	HTTPVersion       string
	TLSMaxVersion     string
	TLSVersion        string
	CACert            string
	Cert              string
	Key               string
	UnixSocket        string
	Ranges            []string
	Retry             int
	RetrySet          bool
	RetryDelay        float64
	RetryDelaySet     bool
	GetFlag           bool
	Verbose           int
	Silent            bool
	UserAgent         string
	Referer           string
	Cookie            string
	HasContentType    bool
	HasAccept         bool
	AllowedProto      string // raw --proto value, e.g. "=https" or "http,https"
	jsonDefaults      bool
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
	// -G flag: data values are moved to the query string after
	// applyFromCurl expands @file and --data-urlencode file forms.
	if r.GetFlag && r.Method == "" {
		r.Method = "GET"
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

	// --json adds its default headers after parsing all flags. This makes an
	// explicit header win regardless of whether it appears before or after
	// --json in the imported command.
	if r.jsonDefaults {
		if !r.HasContentType {
			r.Headers = append(r.Headers, header{Name: "Content-Type", Value: "application/json"})
			r.HasContentType = true
		}
		if !r.HasAccept {
			r.Headers = append(r.Headers, header{Name: "Accept", Value: "application/json"})
			r.HasAccept = true
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

func parseNonNegativeInt(flag, value string) (int, error) {
	if strings.HasPrefix(value, "-") {
		return 0, fmt.Errorf("invalid %s value: %s", flag, value)
	}
	value = strings.TrimPrefix(value, "+")
	if value == "" {
		return 0, fmt.Errorf("invalid %s value: %s", flag, value)
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s value: %s", flag, value)
	}
	return n, nil
}

func parseNonNegativeFloat(flag, value string) (float64, error) {
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 {
		return 0, fmt.Errorf("invalid %s value: %s", flag, value)
	}
	return seconds, nil
}

func unsupportedFailFlag(flag string) error {
	return fmt.Errorf("curl %s is not supported by --from-curl; fetch already exits non-zero for HTTP error statuses but does not suppress the response body", flag)
}

func unsupportedNetrcFlag(flag string) error {
	return fmt.Errorf("curl %s is not supported by --from-curl; use --basic USER:PASS, --bearer TOKEN, or an explicit Authorization header (-H 'Authorization: ...') instead", flag)
}

func unsupportedNoBufferFlag(flag string) error {
	return fmt.Errorf("curl %s is not supported by --from-curl; fetch does not implement curl's unbuffered output mode", flag)
}
