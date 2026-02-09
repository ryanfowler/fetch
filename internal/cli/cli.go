package cli

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/curl"
)

var unixOS = []string{"linux", "darwin", "freebsd", "openbsd", "netbsd", "aix", "dragonfly", "solaris"}

type CLI struct {
	Description    string
	ArgFn          func(s string) error
	Args           []Arguments
	Flags          []Flag
	ExclusiveFlags [][]string
	RequiredFlags  []core.KeyVal[[]string]
}

type Arguments struct {
	Name        string
	Description string
}

type Flag struct {
	Short       string
	Long        string
	Aliases     []string
	Args        string
	Description string
	Default     string
	Values      []core.KeyVal[string]
	HideValues  bool
	IsHidden    bool
	IsSet       func() bool
	OS          []string
	Fn          func(value string) error
}

func parse(cli *CLI, args []string) error {
	short := make(map[string]Flag)
	long := make(map[string]Flag)
	for _, flag := range cli.Flags {
		if !isFlagVisibleOnOS(flag.OS) {
			continue
		}

		if flag.Short != "" {
			assertFlagNotExists(short, flag.Short)
			short[flag.Short] = flag
		}
		if flag.Long != "" {
			assertFlagNotExists(long, flag.Long)
			long[flag.Long] = flag
		}

		for _, alias := range flag.Aliases {
			if len(alias) == 1 {
				assertFlagNotExists(short, alias)
				short[alias] = flag
			} else {
				assertFlagNotExists(long, alias)
				long[alias] = flag
			}
		}
	}

	exclusives := make(map[string][][]string)
	for _, fs := range cli.ExclusiveFlags {
		for _, f := range fs {
			exclusives[f] = append(exclusives[f], fs)
		}
	}

	var err error
	for len(args) > 0 {
		arg := args[0]
		args = args[1:]

		// Parse argument.
		if len(arg) <= 1 || arg[0] != '-' {
			err = cli.ArgFn(arg)
			if err != nil {
				return err
			}
			continue
		}

		// Parse short flag(s).
		if arg[1] != '-' {
			args, err = parseShortFlag(arg, args, short)
			if err != nil {
				return err
			}
			continue
		}

		// Parse long flag.
		if len(arg) > 2 {
			args, err = parseLongFlag(arg, args, long)
			if err != nil {
				return err
			}
			continue
		}

		// "--" means consider everything else arguments.
		err = cli.ArgFn("--")
		if err != nil {
			return err
		}
		for _, arg := range args {
			err = cli.ArgFn(arg)
			if err != nil {
				return err
			}
		}
		break
	}

	// Check exclusive flags.
	for _, exc := range cli.ExclusiveFlags {
		err = validateExclusives(exc, long)
		if err != nil {
			return err
		}
	}

	// Check required flags.
	for _, req := range cli.RequiredFlags {
		err = validateRequired(req, long)
		if err != nil {
			return err
		}
	}

	return nil
}

func parseShortFlag(arg string, args []string, short map[string]Flag) ([]string, error) {
	arg = arg[1:]

	for arg != "" {
		c := arg[:1]
		flag, exists := short[c]
		if !exists {
			return nil, unknownFlagError("-" + c)
		}

		var value string
		if len(arg) >= 2 && arg[1] == '=' {
			// -f=val
			value = arg[2:]
			arg = ""
			if flag.Args == "" {
				return nil, flagNoArgsError("-" + c)
			}
		} else if flag.Args != "" {
			if len(arg) > 1 {
				// -fval
				value = arg[1:]
			} else if len(args) > 0 {
				// -f val
				value = args[0]
				args = args[1:]
			} else {
				return nil, argRequiredError("-" + c)
			}
			arg = ""
		} else {
			arg = arg[1:]
		}

		if err := flag.Fn(value); err != nil {
			return nil, err
		}
	}

	return args, nil
}

func parseLongFlag(arg string, args []string, long map[string]Flag) ([]string, error) {
	name, value, ok := strings.Cut(arg[2:], "=")

	flag, exists := long[name]
	if !exists {
		return nil, unknownFlagError("--" + name)
	}

	if (ok || value != "") && flag.Args == "" {
		return nil, flagNoArgsError("--" + name)
	}

	if flag.Args != "" && value == "" {
		if len(args) == 0 {
			return nil, argRequiredError("--" + name)
		}

		value = args[0]
		args = args[1:]
	}

	if err := flag.Fn(value); err != nil {
		return nil, err
	}

	return args, nil
}

func validateExclusives(exc []string, long map[string]Flag) error {
	var lastSet string
	for _, name := range exc {
		flag := long[name]
		if !flag.IsSet() {
			continue
		}

		if lastSet == "" {
			lastSet = name
			continue
		}

		return newExclusiveFlagsError(lastSet, name)
	}
	return nil
}

func validateRequired(req core.KeyVal[[]string], long map[string]Flag) error {
	flag := long[req.Key]
	if !flag.IsSet() {
		return nil
	}

	// Check if ANY of the required flags is set (OR logic).
	for _, required := range req.Val {
		requiredFlag := long[required]
		if requiredFlag.IsSet() {
			return nil
		}
	}

	// None of the required flags are set.
	return newRequiredFlagError(req.Key, req.Val)
}

func isFlagVisibleOnOS(flagOS []string) bool {
	return len(flagOS) == 0 || slices.Contains(flagOS, runtime.GOOS)
}

func Parse(args []string) (*App, error) {
	var app App

	cli := app.CLI()
	err := parse(cli, args)
	if err != nil {
		return &app, err
	}

	if app.FromCurl != "" {
		if err := app.validateFromCurlExclusives(); err != nil {
			return &app, err
		}
		result, err := curl.Parse(app.FromCurl)
		if err != nil {
			return &app, err
		}
		if err := app.applyFromCurl(result); err != nil {
			return &app, err
		}
	}

	if err := app.validateWSExclusives(); err != nil {
		return &app, err
	}

	return &app, nil
}

// validateWSExclusives checks that ws:// / wss:// scheme is not combined
// with incompatible flags.
func (a *App) validateWSExclusives() error {
	if !a.WS {
		return nil
	}

	type flagCheck struct {
		name  string
		isSet bool
	}
	conflicts := []flagCheck{
		{"discard", a.Discard},
		{"grpc", a.GRPC},
		{"form", len(a.Form) > 0},
		{"multipart", len(a.Multipart) > 0},
		{"xml", a.xmlSet},
		{"edit", a.Edit},
	}

	// The URL scheme was rewritten from ws->http / wss->https during
	// parsing, so reverse the mapping for the error message.
	scheme := "ws"
	if a.URL != nil && a.URL.Scheme == "https" {
		scheme = "wss"
	}

	for _, c := range conflicts {
		if c.isSet {
			return schemeExclusiveError{scheme: scheme, flag: c.name}
		}
	}
	return nil
}

func printHelp(cli *CLI, p *core.Printer) {
	p.WriteString(cli.Description)
	p.WriteString("\n\n")

	p.Set(core.Bold)
	p.Set(core.Underline)
	p.WriteString("Usage")
	p.Reset()
	p.WriteString(": ")

	p.Set(core.Bold)
	p.WriteString("fetch")
	p.Reset()

	if len(cli.Flags) > 0 {
		p.WriteString(" [OPTIONS]")
	}

	for _, arg := range cli.Args {
		p.WriteString(" [")
		p.WriteString(arg.Name)
		p.WriteString("]")
	}
	p.WriteString("\n")

	if len(cli.Args) > 0 {
		p.WriteString("\n")

		p.Set(core.Bold)
		p.Set(core.Underline)
		p.WriteString("Arguments")
		p.Reset()
		p.WriteString(":\n")

		for _, arg := range cli.Args {
			p.WriteString("  [")
			p.WriteString(arg.Name)
			p.WriteString("]  ")
			p.WriteString(arg.Description)
			p.WriteString("\n")
		}
	}

	if len(cli.Flags) > 0 {
		p.WriteString("\n")

		p.Set(core.Bold)
		p.Set(core.Underline)
		p.WriteString("Options")
		p.Reset()
		p.WriteString(":\n")

		maxLen := maxFlagLength(cli.Flags)
		for _, flag := range cli.Flags {
			if flag.IsHidden {
				continue
			}
			if !isFlagVisibleOnOS(flag.OS) {
				continue
			}

			p.Set(core.Bold)
			p.WriteString("  ")

			if flag.Short == "" {
				p.WriteString("    ")
			} else {
				p.WriteString("-")
				p.WriteString(flag.Short)
				p.WriteString(", ")
			}

			p.WriteString("--")
			p.WriteString(flag.Long)
			p.Reset()

			if flag.Args != "" {
				p.WriteString(" <")
				p.WriteString(flag.Args)
				p.WriteString(">")
			}

			p.WriteString("  ")
			for range maxLen - flagLength(flag) {
				p.WriteString(" ")
			}

			p.WriteString(flag.Description)

			if !flag.HideValues && len(flag.Values) > 0 {
				p.WriteString(" [")
				for i, kv := range flag.Values {
					if i > 0 {
						p.WriteString(", ")
					}
					p.WriteString(kv.Key)
				}
				p.WriteString("]")
			}

			if flag.Default != "" {
				p.WriteString(" [default: ")
				p.WriteString(flag.Default)
				p.WriteString("]")
			}

			p.WriteString("\n")
		}
	}
}

func maxFlagLength(fs []Flag) int {
	var out int
	for _, f := range fs {
		if f.IsHidden {
			continue
		}
		len := flagLength(f)
		if len > out {
			out = len
		}
	}
	return out
}

func flagLength(f Flag) int {
	out := len(f.Long)
	if f.Args != "" {
		out += 3 + len(f.Args)
	}
	return out
}

func assertFlagNotExists(m map[string]Flag, value string) {
	if _, ok := m[value]; ok {
		panic(fmt.Sprintf("flag '%s' defined multiple times", value))
	}
}

// validateFromCurlExclusives checks that no request-specifying flags are used
// alongside --from-curl.
func (a *App) validateFromCurlExclusives() error {
	type flagCheck struct {
		name  string
		isSet bool
	}
	conflicts := []flagCheck{
		{"method", a.Method != ""},
		{"header", len(a.Cfg.Headers) > 0},
		{"data", a.dataSet},
		{"json", a.jsonSet},
		{"xml", a.xmlSet},
		{"form", len(a.Form) > 0},
		{"multipart", len(a.Multipart) > 0},
		{"basic", a.Basic != nil},
		{"bearer", a.Bearer != ""},
		{"aws-sigv4", a.AWSSigv4 != nil},
		{"output", a.Output != ""},
		{"remote-name", a.RemoteName},
		{"remote-header-name", a.RemoteHeaderName},
		{"range", len(a.Range) > 0},
		{"unix", a.UnixSocket != ""},
		{"timeout", a.Cfg.Timeout != nil},
		{"connect-timeout", a.Cfg.ConnectTimeout != nil},
		{"redirects", a.Cfg.Redirects != nil},
		{"proxy", a.Cfg.Proxy != nil},
		{"insecure", a.Cfg.Insecure != nil},
		{"tls", a.Cfg.TLS != nil},
		{"http", a.Cfg.HTTP != core.HTTPDefault},
		{"cert", a.Cfg.CertPath != ""},
		{"key", a.Cfg.KeyPath != ""},
		{"ca-cert", len(a.Cfg.CACerts) > 0},
		{"dns-server", a.Cfg.DNSServer != nil},
		{"retry", a.Cfg.Retry != nil},
		{"retry-delay", a.Cfg.RetryDelay != nil},
		{"grpc", a.GRPC},
		{"query", len(a.Cfg.QueryParams) > 0},
	}

	if a.URL != nil {
		return fromCurlExclusiveError{flag: "URL", positional: true}
	}

	for _, c := range conflicts {
		if c.isSet {
			return fromCurlExclusiveError{flag: c.name}
		}
	}
	return nil
}

// applyFromCurl maps a parsed curl Result onto the App fields.
func (a *App) applyFromCurl(r *curl.Result) error {
	// Parse the URL using the same normalization logic as ArgFn.
	rawURL := r.URL
	if rawURL == "" {
		return fmt.Errorf("no URL provided")
	}
	if !strings.Contains(rawURL, "://") && rawURL[0] != '/' {
		rawURL = "//" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "", "http", "https":
	case "ws":
		u.Scheme = "http"
		a.WS = true
	case "wss":
		u.Scheme = "https"
		a.WS = true
	default:
		return fmt.Errorf("unsupported url scheme: %s", u.Scheme)
	}

	// Apply --proto restrictions.
	if r.AllowedProto != "" {
		allowHTTP, allowHTTPS := curl.ParseAllowedProto(r.AllowedProto)
		switch u.Scheme {
		case "":
			// No explicit scheme: pick the most restrictive allowed one.
			if allowHTTPS && !allowHTTP {
				u.Scheme = "https"
			} else if allowHTTP && !allowHTTPS {
				u.Scheme = "http"
			}
		case "http":
			if !allowHTTP {
				return fmt.Errorf("protocol 'http' not allowed by --proto %q", r.AllowedProto)
			}
		case "https":
			if !allowHTTPS {
				return fmt.Errorf("protocol 'https' not allowed by --proto %q", r.AllowedProto)
			}
		}
	}

	a.URL = u

	// Method.
	if r.Method != "" {
		a.Method = r.Method
	}

	// Headers.
	for _, h := range r.Headers {
		if err := a.Cfg.ParseHeader(h.Name + ": " + h.Value); err != nil {
			return err
		}
		if strings.EqualFold(h.Name, "content-type") {
			a.ContentType = h.Value
		}
	}

	// Convenience headers.
	if r.UserAgent != "" {
		if err := a.Cfg.ParseHeader("User-Agent: " + r.UserAgent); err != nil {
			return err
		}
	}
	if r.Referer != "" {
		if err := a.Cfg.ParseHeader("Referer: " + r.Referer); err != nil {
			return err
		}
	}
	if r.Cookie != "" {
		if err := a.Cfg.ParseHeader("Cookie: " + r.Cookie); err != nil {
			return err
		}
	}

	// Data.
	if len(r.DataValues) > 0 {
		// Process each data value individually: raw values are used as-is,
		// non-raw values go through RequestBody for @file expansion,
		// IsURLEncode values read file contents and URL-encode them.
		parts := make([]string, 0, len(r.DataValues))
		for _, dv := range r.DataValues {
			if dv.IsRaw {
				parts = append(parts, dv.Value)
			} else if dv.IsURLEncode {
				encoded, err := urlEncodeFromValue(dv.Value)
				if err != nil {
					return err
				}
				parts = append(parts, encoded)
			} else {
				reader, _, err := RequestBody(dv.Value)
				if err != nil {
					return err
				}
				if c, ok := reader.(io.Closer); ok {
					defer c.Close()
				}
				b, err := io.ReadAll(reader)
				if err != nil {
					return err
				}
				parts = append(parts, string(b))
			}
		}
		a.Data = strings.NewReader(strings.Join(parts, "&"))
		a.dataSet = true

		// Set default content type for -d data if not explicitly set.
		if !r.HasContentType {
			a.ContentType = "application/x-www-form-urlencoded"
		}
	}

	// Upload file.
	if r.UploadFile != "" {
		reader, _, err := RequestBody("@" + r.UploadFile)
		if err != nil {
			return err
		}
		a.Data = reader
		a.dataSet = true
	}

	// Multipart form fields.
	for _, f := range r.FormFields {
		a.Multipart = append(a.Multipart, core.KeyVal[string]{Key: f.Name, Val: f.Value})
	}

	// Authentication.
	if r.BasicAuth != "" {
		user, pass, ok := strings.Cut(r.BasicAuth, ":")
		if !ok {
			return fmt.Errorf("invalid basic auth format, expected USER:PASS")
		}
		a.Basic = &core.KeyVal[string]{Key: user, Val: pass}
	}
	if r.Bearer != "" {
		a.Bearer = r.Bearer
	}
	if r.AWSSigv4 != "" {
		// curl's --aws-sigv4 uses format "aws:amz:REGION:SERVICE"
		// Extract region and service from it.
		region, service, err := parseAWSSigv4(r.AWSSigv4)
		if err != nil {
			return err
		}
		accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
		if accessKey == "" {
			return missingEnvVarErr("AWS_ACCESS_KEY_ID", "aws-sigv4")
		}
		secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
		if secretKey == "" {
			return missingEnvVarErr("AWS_SECRET_ACCESS_KEY", "aws-sigv4")
		}
		a.AWSSigv4 = &aws.Config{
			Region:    region,
			Service:   service,
			AccessKey: accessKey,
			SecretKey: secretKey,
		}
	}

	// Output.
	a.Output = r.Output
	a.RemoteName = r.RemoteName
	a.RemoteHeaderName = r.RemoteHeaderName

	// TLS.
	if r.Insecure {
		v := true
		a.Cfg.Insecure = &v
	}
	if r.TLSVersion != "" {
		if err := a.Cfg.ParseTLS(r.TLSVersion); err != nil {
			return err
		}
	}
	if r.CACert != "" {
		if err := a.Cfg.ParseCACerts(r.CACert); err != nil {
			return err
		}
	}
	if r.Cert != "" {
		if err := a.Cfg.ParseCert(r.Cert); err != nil {
			return err
		}
	}
	if r.Key != "" {
		if err := a.Cfg.ParseKey(r.Key); err != nil {
			return err
		}
	}

	// Network.
	if r.FollowRedirects {
		redirects := 10
		if r.MaxRedirects > 0 {
			redirects = r.MaxRedirects
		}
		a.Cfg.Redirects = &redirects
	} else if r.MaxRedirects > 0 {
		a.Cfg.Redirects = &r.MaxRedirects
	}
	if r.Timeout > 0 {
		if err := a.Cfg.ParseTimeout(strconv.FormatFloat(r.Timeout, 'f', -1, 64)); err != nil {
			return err
		}
	}
	if r.ConnectTimeout > 0 {
		if err := a.Cfg.ParseConnectTimeout(strconv.FormatFloat(r.ConnectTimeout, 'f', -1, 64)); err != nil {
			return err
		}
	}
	if r.Proxy != "" {
		if err := a.Cfg.ParseProxy(r.Proxy); err != nil {
			return err
		}
	}
	if r.UnixSocket != "" {
		a.UnixSocket = r.UnixSocket
	}
	if r.DoHURL != "" {
		if err := a.Cfg.ParseDNSServer(r.DoHURL); err != nil {
			return err
		}
	}
	if r.Retry > 0 {
		a.Cfg.Retry = &r.Retry
	}
	if r.RetryDelay > 0 {
		a.Cfg.RetryDelay = core.PointerTo(time.Duration(float64(time.Second) * r.RetryDelay))
	}

	// Ranges.
	a.Range = r.Ranges

	// HTTP version.
	switch r.HTTPVersion {
	case "1.0", "1.1":
		a.Cfg.HTTP = core.HTTP1
	case "2":
		a.Cfg.HTTP = core.HTTP2
	case "3":
		a.Cfg.HTTP = core.HTTP3
	}

	// Verbosity.
	if r.Verbose > 0 {
		a.Cfg.Verbosity = &r.Verbose
	}
	if r.Silent {
		v := true
		a.Cfg.Silent = &v
	}

	return nil
}

// parseAWSSigv4 parses curl's --aws-sigv4 format.
// curl uses "aws:amz:REGION:SERVICE" or just "REGION/SERVICE".
func parseAWSSigv4(s string) (region, service string, err error) {
	// Try curl's "provider:signer:REGION:SERVICE" format first.
	parts := strings.Split(s, ":")
	if len(parts) == 4 {
		if parts[0] != "aws" || parts[1] != "amz" {
			fmt.Fprintf(os.Stderr, "warning: --aws-sigv4 provider %q and signer %q are ignored; using AWS defaults\n", parts[0], parts[1])
		}
		region, service = parts[2], parts[3]
		if region == "" || service == "" {
			return "", "", fmt.Errorf("invalid aws-sigv4 format: region and service must be non-empty in %q", s)
		}
		return region, service, nil
	}
	// Try "REGION/SERVICE" format (fetch native).
	var ok bool
	if region, service, ok = strings.Cut(s, "/"); ok {
		if region == "" || service == "" {
			return "", "", fmt.Errorf("invalid aws-sigv4 format: region and service must be non-empty in %q", s)
		}
		return region, service, nil
	}
	return "", "", fmt.Errorf("invalid aws-sigv4 format: %q, expected 'aws:amz:REGION:SERVICE' or 'REGION/SERVICE'", s)
}

// urlEncodeFromValue handles --data-urlencode file forms:
//   - "@filename" reads the file and URL-encodes the contents.
//   - "name@filename" reads the file, URL-encodes the contents, and prepends "name=".
func urlEncodeFromValue(s string) (string, error) {
	if strings.HasPrefix(s, "@") {
		// @filename form.
		content, err := readFileForURLEncode(s[1:])
		if err != nil {
			return "", err
		}
		return url.QueryEscape(content), nil
	}

	// name@filename form.
	name, filename, ok := strings.Cut(s, "@")
	if !ok || name == "" {
		return url.QueryEscape(s), nil
	}
	content, err := readFileForURLEncode(filename)
	if err != nil {
		return "", err
	}
	return name + "=" + url.QueryEscape(content), nil
}

func readFileForURLEncode(path string) (string, error) {
	reader, _, err := RequestBody("@" + path)
	if err != nil {
		return "", err
	}
	if c, ok := reader.(io.Closer); ok {
		defer c.Close()
	}
	b, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
