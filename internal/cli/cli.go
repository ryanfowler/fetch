package cli

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/client"
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
	// Mark this before parsing so a one-shot stdin body can skip MIME sniffing
	// even when --webtransport appears after -d @-.
	for _, arg := range args {
		if arg == "--webtransport" {
			app.WebTransport = true
			break
		}
	}

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
	if err := ValidateWebTransport(&app); err != nil {
		return &app, err
	}

	if err := validateSchemeExclusives(&app, cli, long); err != nil {
		return &app, err
	}
	if app.WS && app.Cfg.HTTP > core.HTTP1 {
		return &app, fmt.Errorf("cannot use WebSocket with %s", app.Cfg.HTTP.String())
	}
	if app.URL != nil && !app.WS && app.WSInteractive != core.WSInteractiveAuto {
		return &app, fmt.Errorf("'--ws-interactive' requires a ws:// or wss:// URL")
	}
	if err := validateGRPCModes(&app, cli, long); err != nil {
		return &app, err
	}

	return &app, nil
}

// ValidateWebTransport validates mode-specific options after CLI and config
// values have been merged. It performs no I/O and is safe to call preflight.
func ValidateWebTransport(app *App) error {
	if app == nil || !app.WebTransport {
		if app != nil && (app.wtModeSet || app.wtDgramModeSet || len(app.WTProtocols) > 0) {
			return errors.New("WebTransport options require --webtransport")
		}
		return nil
	}
	if app.WS {
		return errors.New("WebSocket and WebTransport cannot be used together")
	}
	if app.InspectDNS || app.InspectTLS || app.Update || app.CheckUpdate || app.Skill || app.InstallSkill != "" || app.UninstallSkill != "" {
		return errors.New("WebTransport cannot be combined with an inspection, update, or skill command")
	}
	if app.wtDgramModeSet && app.WTMode != core.WTDatagram {
		return errors.New("--wt-datagram-mode requires --wt-mode datagram")
	}
	if name, ok := app.CLI().Options().Unsupported(ModeWebTransport); ok {
		return fmt.Errorf("--%s cannot be used with WebTransport", name)
	}
	if app.URL == nil {
		return nil
	}
	if !strings.EqualFold(app.URL.Scheme, "https") {
		return errors.New("WebTransport requires an https:// URL")
	}
	if app.Cfg.HTTP == core.HTTP1 || app.Cfg.HTTP == core.HTTP2 {
		return fmt.Errorf("WebTransport requires HTTP/3; cannot use %s", app.Cfg.HTTP.String())
	}
	if app.Cfg.Format != core.FormatUnknown {
		return errors.New("--format cannot be used with WebTransport")
	}
	if app.Cfg.TLSMax != nil && *app.Cfg.TLSMax < tls.VersionTLS13 {
		return errors.New("WebTransport requires max-tls 1.3 or higher")
	}
	// These values can come from a merged config file, so registry IsSet
	// checks alone are not sufficient here.
	for _, unsupported := range []struct {
		name string
		set  bool
	}{
		{"compress", app.Cfg.Compress != core.CompressionUnknown},
		{"copy", app.Cfg.Copy != nil}, {"ignore-status", app.Cfg.IgnoreStatus != nil},
		{"no-encode", app.Cfg.NoEncode != nil}, {"redirects", app.Cfg.Redirects != nil},
		{"retry", app.Cfg.Retry != nil}, {"retry-delay", app.Cfg.RetryDelay != nil},
		{"retry-unsafe", app.Cfg.RetryUnsafe != nil},
	} {
		if unsupported.set {
			return fmt.Errorf("--%s cannot be used with WebTransport", unsupported.name)
		}
	}
	if app.UnixSocket != "" {
		return errors.New("WebTransport cannot be used with a unix socket")
	}
	if app.URL != nil {
		decision, err := client.SelectProxy(app.Cfg.Proxy, app.URL)
		if err != nil {
			return err
		}
		if decision.URL != nil {
			return errors.New("WebTransport cannot be used with a proxy")
		}
	}
	for _, h := range app.Cfg.Headers {
		if strings.EqualFold(h.Key, "Host") {
			return errors.New("host header cannot be used with WebTransport")
		}
		if strings.EqualFold(h.Key, "WT-Available-Protocols") || strings.EqualFold(h.Key, "WT-Protocol") {
			return fmt.Errorf("header %q cannot be supplied with WebTransport", h.Key)
		}
	}
	return nil
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
	// Skill operations are metadata commands. Keep their allowed surface
	// deliberately small so presentation, config, update, and request flags
	// cannot be silently ignored.
	allowed := map[string]bool{
		"skill": true, "install-skill": true, "uninstall-skill": true,
		"scope": true, "force": true, "dry-run": true,
	}
	for _, flag := range cli.Options().Flags() {
		if flag.IsSet() && !allowed[flag.Long] {
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

	// Data. A single ordinary -d @file or -d @- value can use the native
	// lazy body source. Every other form needs materialization for curl's
	// concatenation, query, or URL-encoding semantics.
	if len(r.DataValues) > 0 {
		if !r.GetFlag && len(r.DataValues) == 1 && isStreamingCurlData(r.DataValues[0]) {
			reader, _, err := RequestBody(r.DataValues[0].Value)
			if err != nil {
				return err
			}
			a.Data = reader
			a.dataSet = true
		} else {
			data, err := materializeCurlData(r.DataValues)
			if err != nil {
				return err
			}
			if r.GetFlag {
				appendRawQuery(a.URL, string(data))
			} else {
				a.Data = bytes.NewReader(data)
				a.dataSet = true
			}
		}

		// Set default content type for -d data if not explicitly set.
		if !r.HasContentType && !r.GetFlag {
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
	for _, value := range r.Resolve {
		if err := a.parseResolveFlag(value); err != nil {
			return err
		}
	}
	if r.RetrySet {
		if err := a.Cfg.ParseRetry(strconv.Itoa(r.Retry)); err != nil {
			return err
		}
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

func isStreamingCurlData(value curl.DataValue) bool {
	return !value.IsRaw && !value.IsURLEncode && strings.HasPrefix(value.Value, "@")
}

// materializeCurlData applies curl's ordered ampersand concatenation while
// keeping the complete generated body within the shared materialization cap.
// File and stdin sources are read in chunks, so an over-limit source is not
// first copied into an unbounded intermediate buffer.
func materializeCurlData(values []curl.DataValue) ([]byte, error) {
	out := core.NewBoundedBuffer(core.MaxCompositeMaterialization, "curl request body")
	for i, value := range values {
		if i > 0 {
			if _, err := out.Write([]byte{'&'}); err != nil {
				return nil, err
			}
		}
		if err := appendCurlDataValue(out, value); err != nil {
			return nil, err
		}
	}
	return append([]byte(nil), out.Bytes()...), nil
}

func appendCurlDataValue(out *core.BoundedBuffer, value curl.DataValue) error {
	if value.IsRaw {
		_, err := out.Write([]byte(value.Value))
		return err
	}
	if value.IsURLEncode {
		return appendCurlURLEncodedValue(out, value.Value)
	}
	return appendCurlBodyValue(out, value.Value)
}

func appendCurlBodyValue(out *core.BoundedBuffer, value string) error {
	reader, _, err := RequestBody(value)
	if err != nil {
		return err
	}
	if closer, ok := reader.(io.Closer); ok {
		defer closer.Close()
	}
	return appendCurlReader(out, reader)
}

func appendCurlURLEncodedValue(out *core.BoundedBuffer, value string) error {
	if strings.HasPrefix(value, "@") {
		return appendCurlURLEncodedFile(out, value[1:])
	}
	if name, path, ok := strings.Cut(value, "@"); ok && name != "" {
		if _, err := out.Write([]byte(name + "=")); err != nil {
			return err
		}
		return appendCurlURLEncodedFile(out, path)
	}
	_, err := out.Write([]byte(url.QueryEscape(value)))
	return err
}

func appendCurlURLEncodedFile(out *core.BoundedBuffer, path string) error {
	reader, _, err := RequestBody("@" + path)
	if err != nil {
		return err
	}
	if closer, ok := reader.(io.Closer); ok {
		defer closer.Close()
	}
	return appendCurlEscapedReader(out, reader)
}

func appendCurlReader(out *core.BoundedBuffer, reader io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			if _, writeErr := out.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func appendCurlEscapedReader(out *core.BoundedBuffer, reader io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			if writeErr := appendCurlEscapedBytes(out, buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func appendCurlEscapedBytes(out *core.BoundedBuffer, data []byte) error {
	const hex = "0123456789ABCDEF"
	for _, b := range data {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '-', b == '_', b == '.', b == '~':
			if _, err := out.Write([]byte{b}); err != nil {
				return err
			}
		case b == ' ':
			if _, err := out.Write([]byte{'+'}); err != nil {
				return err
			}
		default:
			encoded := []byte{'%', hex[b>>4], hex[b&0x0f]}
			if _, err := out.Write(encoded); err != nil {
				return err
			}
		}
	}
	return nil
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
