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

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/curl"
)

var unixOS = []string{"linux", "darwin", "freebsd", "openbsd", "netbsd", "aix", "dragonfly", "solaris"}

const curlDefaultMaxRedirects = 50

type CLI struct {
	Description    string
	ArgFn          func(s string) error
	Args           []Arguments
	Flags          []Flag
	ExclusiveFlags [][]string
	RequiredFlags  []core.KeyVal[[]string]

	// SchemeExclusiveFlags maps URL schemes (e.g. "ws", "wss") to flags
	// that cannot be used with that scheme.
	SchemeExclusiveFlags map[string][]string

	// FromCurlExclusiveFlags lists flags that cannot be used alongside
	// --from-curl.
	FromCurlExclusiveFlags []string

	// OnOptionSet receives the canonical option name after a successful
	// explicit CLI parse. It is used to preserve source provenance.
	OnOptionSet func(canonical string)
	registry    *OptionRegistry
}

type Arguments struct {
	Name        string
	Description string
}

type Flag struct {
	Short       string
	Long        string
	Aliases     []string
	AliasValues map[string]string
	Args        string
	OptionalArg bool
	Description string
	Default     string
	Values      []core.KeyVal[string]
	HideValues  bool
	IsHidden    bool
	IsSet       func() bool
	OS          []string
	Fn          func(value string) error

	// Registry metadata. These fields keep the option contract next to the
	// parser definition so validation, help, completion, and diagnostics share
	// the same source of truth.
	ConfigKey     string
	Repeatable    bool
	Schemes       []string
	Modes         []OptionMode
	Conflicts     []string
	Requires      []string
	IgnoredIn     []OptionMode
	IgnoreLabel   string
	FromCurl      bool
	UnsupportedIn []OptionMode
}

// parseWithFlags parses the CLI arguments and returns the long flag map for
// use in post-parse validation.
func parseWithFlags(cli *CLI, args []string) (map[string]Flag, error) {
	registry := cli.Options()
	short := registry.ShortFlags()
	long := registry.LongFlags()

	var err error
	for len(args) > 0 {
		arg := args[0]
		args = args[1:]

		// Parse argument.
		if len(arg) <= 1 || arg[0] != '-' {
			err = cli.ArgFn(arg)
			if err != nil {
				return nil, err
			}
			continue
		}

		// Parse short flag(s).
		if arg[1] != '-' {
			args, err = parseShortFlag(cli, arg, args, short)
			if err != nil {
				return nil, err
			}
			continue
		}

		// Parse long flag.
		if len(arg) > 2 {
			args, err = parseLongFlag(cli, arg, args, long)
			if err != nil {
				return nil, err
			}
			continue
		}

		// "--" means consider everything else arguments.
		err = cli.ArgFn("--")
		if err != nil {
			return nil, err
		}
		for _, arg := range args {
			err = cli.ArgFn(arg)
			if err != nil {
				return nil, err
			}
		}
		break
	}

	if err = registry.Validate(); err != nil {
		return nil, err
	}

	return long, nil
}

func parseShortFlag(cli *CLI, arg string, args []string, short map[string]Flag) ([]string, error) {
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
		if cli.OnOptionSet != nil {
			cli.OnOptionSet(flag.Long)
		}
	}

	return args, nil
}

func parseLongFlag(cli *CLI, arg string, args []string, long map[string]Flag) ([]string, error) {
	name, value, ok := strings.Cut(arg[2:], "=")

	flag, exists := long[name]
	if !exists {
		return nil, unknownFlagError("--" + name)
	}

	fixedValue, fixedAlias := flag.AliasValues[name]
	if fixedAlias && (ok || value != "") {
		return nil, flagNoArgsError("--" + name)
	}
	if (ok || value != "") && flag.Args == "" {
		return nil, flagNoArgsError("--" + name)
	}

	if fixedAlias {
		value = fixedValue
	} else if flag.Args != "" && !ok && !flag.OptionalArg {
		if len(args) == 0 {
			return nil, argRequiredError("--" + name)
		}

		value = args[0]
		args = args[1:]
	} else if flag.Args != "" && !ok && flag.OptionalArg && len(args) > 0 {
		if args[0] != "--" && (len(args[0]) == 0 || args[0][0] != '-') {
			value = args[0]
			args = args[1:]
		}
	}

	if err := flag.Fn(value); err != nil {
		return nil, err
	}
	if cli.OnOptionSet != nil {
		cli.OnOptionSet(flag.Long)
	}

	return args, nil
}

// Options returns the registry for this CLI definition. The registry is
// cached so all consumers of one definition see the same enriched metadata.
func (cli *CLI) Options() *OptionRegistry {
	if cli.registry == nil {
		cli.registry = newOptionRegistry(cli)
		cli.Flags = cli.registry.Flags()
	}
	return cli.registry
}

func isFlagVisibleOnOS(flagOS []string) bool {
	return len(flagOS) == 0 || slices.Contains(flagOS, runtime.GOOS)
}

func Parse(args []string) (*App, error) {
	var app App

	cli := app.CLI()
	long, err := parseWithFlags(cli, args)
	if err != nil {
		return &app, err
	}
	if err := validateEquivalentAliases(&app); err != nil {
		return &app, err
	}

	if app.FromCurl != "" {
		if err := validateFromCurlExclusives(&app, cli, long); err != nil {
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
	if app.Method == "" && app.hasRequestBody() {
		app.Method = "POST"
	}

	if err := validateSkillMode(&app, cli); err != nil {
		return &app, err
	}
	if app.wsMessageModeSet && !app.WS {
		return &app, fmt.Errorf("'--ws-message-mode' requires a ws:// or wss:// URL")
	}

	if err := validateSchemeExclusives(&app, cli, long); err != nil {
		return &app, err
	}
	if app.URL != nil && !app.WS && app.WSInteractive != core.WSInteractiveAuto {
		return &app, fmt.Errorf("'--ws-interactive' requires a ws:// or wss:// URL")
	}
	if err := validateGRPCModes(&app, cli, long); err != nil {
		return &app, err
	}

	return &app, nil
}

func validateEquivalentAliases(app *App) error {
	if app.compressSet && app.noEncodeSet && app.explicitCompress != core.CompressionOff {
		return newExclusiveFlagsError("compress", "no-encode")
	}
	if app.pagerSet && app.noPagerSet && app.Cfg.Pager != core.PagerOff {
		return newExclusiveFlagsError("no-pager", "pager")
	}
	return nil
}

func validateSkillMode(app *App, cli *CLI) error {
	if !app.Skill && app.InstallSkill == "" && app.UninstallSkill == "" {
		return nil
	}
	if app.URL != nil {
		return fmt.Errorf("skill commands cannot be combined with a URL")
	}
	requestOnly := map[string]bool{
		"article": true, "compress": true, "data": true, "digest": true, "dns-server": true,
		"ech": true, "edit": true, "form": true, "grpc": true, "grpc-describe": true,
		"grpc-list": true, "har": true, "header": true, "http": true, "image": true,
		"inspect-dns": true, "inspect-tls": true, "method": true, "multipart": true,
		"output": true, "query": true, "range": true, "redirects": true, "remote-header-name": true,
		"remote-name": true, "retry": true, "retry-delay": true, "session": true, "unix": true,
		"ws-message-mode": true, "ws-interactive": true, "basic": true, "bearer": true,
		"aws-sigv4": true, "ca-cert": true, "cert": true, "key": true, "insecure": true,
	}
	for _, flag := range cli.Options().Flags() {
		if flag.IsSet() && requestOnly[flag.Long] {
			return newExclusiveFlagsError(flag.Long, "skill command")
		}
	}
	return nil
}

// validateSchemeExclusives checks that scheme-specific exclusive flags
// (e.g. ws:// / wss:// flags) are not combined with incompatible flags.
func validateSchemeExclusives(app *App, cli *CLI, long map[string]Flag) error {
	if !app.WS {
		return nil
	}

	// The URL scheme was rewritten from ws->http / wss->https during
	// parsing, so reverse the mapping for the error message.
	scheme := "ws"
	if app.URL != nil && app.URL.Scheme == "https" {
		scheme = "wss"
	}

	return cli.Options().ValidateScheme(scheme)
}

func validateGRPCModes(app *App, cli *CLI, long map[string]Flag) error {
	if !app.HasProtoSchema() && !app.HasGRPCMode() {
		return nil
	}

	if !app.HasGRPCMode() {
		name := "proto-file"
		if app.ProtoDesc != "" {
			name = "proto-desc"
		}
		return newRequiredFlagError(name, []string{"grpc", "grpc-list", "grpc-describe"})
	}

	if !app.HasGRPCDiscovery() {
		return nil
	}

	if name, ok := cli.Options().Unsupported(ModeGRPCDiscovery); ok {
		base := "grpc-list"
		if app.GRPCDescribe != "" {
			base = "grpc-describe"
		}
		return newExclusiveFlagsError(base, name)
	}

	return nil
}

func printHelp(cli *CLI, p *core.Printer) {
	flags := cli.Options().Flags()
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

	if len(flags) > 0 {
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

	if len(flags) > 0 {
		p.WriteString("\n")

		p.Set(core.Bold)
		p.Set(core.Underline)
		p.WriteString("Options")
		p.Reset()
		p.WriteString(":\n")

		maxLen := maxFlagLength(flags)
		for _, flag := range flags {
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
				if flag.OptionalArg {
					p.WriteString(" [<")
				} else {
					p.WriteString(" <")
				}
				p.WriteString(flag.Args)
				p.WriteString(">")
				if flag.OptionalArg {
					p.WriteString("]")
				}
			}

			p.WriteString("  ")
			for range maxLen - flagLength(flag) {
				p.WriteString(" ")
			}

			p.WriteString(flag.Description)

			if !flag.HideValues && len(flag.Values) > 0 {
				suffix := flagValuesSuffix(flag)
				lineLength := 2 + 4 + 2 + len(flag.Long)
				if flag.Short != "" {
					lineLength = 2 + len(flag.Short) + 4 + 2 + len(flag.Long)
				}
				if flag.Args != "" {
					lineLength += 3 + len(flag.Args)
					if flag.OptionalArg {
						lineLength++
					}
				}
				lineLength += 2 + maxLen - flagLength(flag) + len(flag.Description)
				if lineLength+len(suffix) > 80 {
					p.WriteString("\n          values: ")
					p.WriteString(suffix[1:])
				} else {
					p.WriteString(suffix)
				}
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

func flagValuesSuffix(flag Flag) string {
	var values strings.Builder
	values.WriteString(" [")
	for i, kv := range flag.Values {
		if i > 0 {
			values.WriteString(", ")
		}
		values.WriteString(kv.Key)
	}
	values.WriteByte(']')
	return values.String()
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

// validateFromCurlExclusives checks that no request-specifying flags are used
// alongside --from-curl.
func validateFromCurlExclusives(app *App, cli *CLI, long map[string]Flag) error {
	if app.URL != nil {
		return fromCurlExclusiveError{flag: "URL", positional: true}
	}

	for _, flag := range cli.Options().Flags() {
		if flag.FromCurl && flag.IsSet() {
			return fromCurlExclusiveError{flag: flag.Long}
		}
	}
	return nil
}

// applyFromCurl maps a parsed curl Result onto the App fields.
func (a *App) applyFromCurl(r *curl.Result) error {
	// Parse the URL using the shared normalization logic.
	if r.URL == "" {
		return fmt.Errorf("no URL provided")
	}
	a.SchemelessURL = !hasAuthorityScheme(r.URL)
	u, isWS, err := parseURL(r.URL)
	if err != nil {
		return err
	}
	a.WS = a.WS || isWS

	// Apply --proto restrictions.
	if r.AllowedProto != "" {
		allowHTTP, allowHTTPS := curl.ParseAllowedProto(r.AllowedProto)
		if a.SchemelessURL {
			// A schemeless URL may be forced to the only protocol allowed by
			// curl's --proto setting.
			if allowHTTPS && !allowHTTP {
				u.Scheme = "https"
			} else if allowHTTP && !allowHTTPS {
				u.Scheme = "http"
			}
		}
		switch u.Scheme {
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
				b, err := core.ReadAllLimited(reader, core.MaxCompositeMaterialization, "curl request body")
				if c, ok := reader.(io.Closer); ok {
					c.Close()
				}
				if err != nil {
					return err
				}
				parts = append(parts, string(b))
			}
		}
		data := strings.Join(parts, "&")
		if r.GetFlag {
			appendRawQuery(a.URL, data)
		} else {
			a.Data = strings.NewReader(data)
			a.dataSet = true

			// Set default content type for -d data if not explicitly set.
			if !r.HasContentType {
				a.ContentType = "application/x-www-form-urlencoded"
			}
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
		if err := a.parseMultipartFlag(f.Name + "=" + f.Value); err != nil {
			return err
		}
	}

	// Authentication.
	if r.BasicAuth != "" {
		user, pass, ok := strings.Cut(r.BasicAuth, ":")
		if !ok {
			return fmt.Errorf("invalid basic auth format, expected USER:PASS")
		}
		if r.DigestAuth {
			a.Digest = &core.KeyVal[string]{Key: user, Val: pass}
		} else {
			a.Basic = &core.KeyVal[string]{Key: user, Val: pass}
		}
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
		cfg, err := buildAWSConfig(region, service)
		if err != nil {
			return err
		}
		a.AWSSigv4 = cfg
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
	if r.ECH != "" {
		mode := r.ECH
		if mode == "hard" || mode == "true" {
			mode = "on"
		} else if mode == "false" {
			mode = "off"
		}
		if err := a.Cfg.ParseECH(mode); err != nil {
			return err
		}
	}
	if r.TLSVersion != "" {
		if err := a.Cfg.ParseTLS(r.TLSVersion); err != nil {
			return err
		}
	}
	if r.TLSMaxVersion != "" {
		if err := a.Cfg.ParseMaxTLS(r.TLSMaxVersion); err != nil {
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
	redirects := 0
	if r.FollowRedirects {
		redirects = curlDefaultMaxRedirects
		if r.MaxRedirectsSet {
			redirects = r.MaxRedirects
		}
	}
	a.Cfg.Redirects = &redirects
	if r.TimeoutSet {
		if err := a.Cfg.ParseTimeout(strconv.FormatFloat(r.Timeout, 'f', -1, 64)); err != nil {
			return err
		}
	}
	if r.ConnectTimeoutSet {
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
	if r.RetrySet {
		a.Cfg.Retry = &r.Retry
	}
	if r.RetryDelaySet {
		a.Cfg.RetryDelay = new(time.Duration(float64(time.Second) * r.RetryDelay))
	}

	// Ranges.
	for _, rng := range r.Ranges {
		if err := a.parseRangeFlag(rng); err != nil {
			return err
		}
	}

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

	a.markCurlOptions(r)

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
	b, err := core.ReadAllLimited(reader, core.MaxCompositeMaterialization, "curl request body")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func appendRawQuery(u *url.URL, query string) {
	if query == "" {
		return
	}
	if u.RawQuery == "" {
		u.RawQuery = query
		return
	}
	u.RawQuery += "&" + query
}
