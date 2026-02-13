package curl

import (
	"fmt"
	"strconv"
	"strings"
)

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
