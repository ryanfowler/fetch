package cli

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/config"
	"github.com/ryanfowler/fetch/internal/core"
)

// App represents the full configuration for a fetch invocation.
type App struct {
	URL           *url.URL
	ExtraArgs     []string
	SchemelessURL bool

	Cfg config.Config

	AWSSigv4         *aws.Config
	Basic            *core.KeyVal[string]
	Bearer           string
	Digest           *core.KeyVal[string]
	BuildInfo        bool
	Clobber          bool
	Complete         string
	ConfigPath       string
	ContentType      string
	Data             io.Reader
	Discard          bool
	DryRun           bool
	Edit             bool
	Article          bool
	Form             []core.KeyVal[string]
	FromCurl         string
	GRPC             bool
	GRPCDescribe     string
	GRPCList         bool
	HAR              string
	Help             bool
	InspectDNS       bool
	InspectTLS       bool
	Skill            bool
	InstallSkill     string
	UninstallSkill   string
	Scope            string
	Force            bool
	SortHeaders      bool
	WS               bool // set when URL scheme is ws:// or wss://
	Method           string
	Multipart        []core.KeyVal[string]
	Output           string
	ProtoDesc        string
	ProtoFiles       []string
	ProtoImports     []string
	Range            []string
	RemoteHeaderName bool
	RemoteName       bool
	UnixSocket       string
	Update           bool
	Version          bool
	WSInteractive    core.WSInteractiveMode
	WSMessageMode    core.WSMessageMode

	dataSet          bool
	jsonSet          bool
	xmlSet           bool
	compressSet      bool
	explicitCompress core.CompressionMode
	noEncodeSet      bool
	pagerSet         bool
	noPagerSet       bool
	wsMessageModeSet bool

	provenance map[string]OptionProvenance
}

func (a *App) PrintHelp(p *core.Printer) {
	printHelp(a.CLI(), p)
}

func (a *App) HasGRPCDiscovery() bool {
	return a.GRPCList || a.GRPCDescribe != ""
}

func (a *App) HasGRPCMode() bool {
	return a.GRPC || a.HasGRPCDiscovery()
}

func (a *App) HasProtoSchema() bool {
	return len(a.ProtoFiles) > 0 || a.ProtoDesc != ""
}

func (a *App) CLI() *CLI {
	var extraArgs bool
	cli := &CLI{
		Description: "fetch is a modern HTTP(S) client for the command line",
		OnOptionSet: a.markCLIOption,
		Args: []Arguments{
			{Name: "URL", Description: "The URL to make a request to"},
		},
		ArgFn: func(s string) error {
			if extraArgs {
				a.ExtraArgs = append(a.ExtraArgs, s)
				return nil
			}
			if s == "--" {
				if a.Complete != "" {
					extraArgs = true
				}
				return nil
			}

			// Otherwise, parse the provided URL.
			if a.URL != nil {
				return fmt.Errorf("unexpected argument: %q", s)
			}
			a.SchemelessURL = !hasAuthorityScheme(s)
			u, isWS, err := parseURL(s)
			if err != nil {
				return err
			}
			a.URL = u
			a.WS = a.WS || isWS
			return nil
		},
		Flags: []Flag{
			boolFlag(&a.Article, "article", "", "Extract readable article content"),

			// cfgFlag: delegates to config parser
			cfgFlag("auto-update", "", "(ENABLED|INTERVAL)", "Enable/disable auto-updates",
				func() bool { return a.Cfg.AutoUpdate != nil }, a.Cfg.ParseAutoUpdate).
				WithHidden(true),

			// Custom: AWS signature V4
			{
				Long:        "aws-sigv4",
				Args:        "REGION/SERVICE",
				Description: "Sign the request using AWS signature V4",
				IsSet:       func() bool { return a.AWSSigv4 != nil },
				Fn:          a.parseAWSSigv4Flag,
			},

			// Custom: basic auth parsing
			{
				Long:        "basic",
				Args:        "USER:PASS",
				Description: "Enable HTTP basic authentication",
				IsSet:       func() bool { return a.Basic != nil },
				Fn:          a.parseBasicFlag,
			},

			// stringFlag: simple string value
			stringFlag(&a.Bearer, "bearer", "", "TOKEN", "Enable HTTP bearer authentication"),
			boolFlag(&a.BuildInfo, "buildinfo", "", "Print the build information"),

			// cfgFlag: delegates to config parser
			cfgFlag("ca-cert", "", "PATH", "CA certificate file path",
				func() bool { return len(a.Cfg.CACerts) > 0 }, a.Cfg.ParseCACerts),

			// Custom: file check + config parse
			{
				Long:        "cert",
				Args:        "PATH",
				Description: "Client certificate for mTLS",
				IsSet:       func() bool { return a.Cfg.CertPath != "" },
				Fn:          a.parseCertFlag,
			},

			boolFlag(&a.Clobber, "clobber", "", "Overwrite existing output file"),

			cfgFlag("color", "", "OPTION", "Enable/disable color",
				func() bool { return a.Cfg.Color != core.ColorUnknown }, a.Cfg.ParseColor).
				WithAliases("colour").
				WithValues([]core.KeyVal[string]{
					{Key: "auto", Val: "Automatically determine color"},
					{Key: "off", Val: "Disable color output"},
					{Key: "on", Val: "Enable color output"},
				}),

			stringFlag(&a.Complete, "complete", "", "SHELL", "Output shell completion").
				WithValues([]core.KeyVal[string]{
					{Key: "bash"}, {Key: "fish"}, {Key: "zsh"},
				}).
				WithHideValues(),

			Flag{
				Long:        "compress",
				Args:        "MODE",
				Description: "Response compression",
				IsSet:       func() bool { return a.compressSet },
				Fn: func(value string) error {
					previous := a.Cfg.Compress
					if err := a.Cfg.ParseCompress(value); err != nil {
						return err
					}
					if a.compressSet && a.explicitCompress != a.Cfg.Compress {
						a.Cfg.Compress = previous
						return core.NewValueError("compress", value, "conflicts with the previously selected compression mode", false)
					}
					a.compressSet = true
					a.explicitCompress = a.Cfg.Compress
					return nil
				},
			}.
				WithValues([]core.KeyVal[string]{
					{Key: "auto", Val: "Request and decode gzip, Brotli, and zstd"},
					{Key: "br", Val: "Request and decode Brotli"},
					{Key: "brotli", Val: "Alias for br"},
					{Key: "gzip", Val: "Request and decode gzip"},
					{Key: "zstd", Val: "Request and decode zstd"},
					{Key: "off", Val: "Do not negotiate or decode compression"},
				}),

			stringFlag(&a.ConfigPath, "config", "c", "PATH", "Path to config file"),

			cfgFlag("connect-timeout", "", "SECONDS", "Timeout for connection establishment",
				func() bool { return a.Cfg.ConnectTimeout != nil }, a.Cfg.ParseConnectTimeout),

			ptrBoolFlag(&a.Cfg.Copy, "copy", "", "Copy the response body to clipboard"),

			// Custom: data with content type detection
			{
				Short:       "d",
				Long:        "data",
				Args:        "[@]VALUE",
				Description: "Send a request body",
				IsSet:       func() bool { return a.dataSet || (!a.jsonSet && !a.xmlSet && a.Data != nil) },
				Fn:          a.parseDataFlag,
			},

			// Custom: digest auth parsing
			{
				Long:        "digest",
				Args:        "USER:PASS",
				Description: "Enable HTTP digest authentication",
				IsSet:       func() bool { return a.Digest != nil },
				Fn:          a.parseDigestFlag,
			},

			boolFlag(&a.Discard, "discard", "", "Discard the response body"),

			cfgFlag("dns-server", "", "IP[:PORT]|URL", "DNS server IP or DoH URL",
				func() bool { return a.Cfg.DNSServer != nil }, a.Cfg.ParseDNSServer),

			boolFlag(&a.DryRun, "dry-run", "", "Print out the request info and exit"),

			cfgFlag("ech", "", "OPTION", "Configure Encrypted ClientHello",
				func() bool { return a.Cfg.ECH != core.ECHUnknown }, a.Cfg.ParseECH).
				WithValues([]core.KeyVal[string]{
					{Key: "auto", Val: "Use ECH when available"},
					{Key: "on", Val: "Require ECH"},
					{Key: "off", Val: "Disable ECH"},
				}),

			boolFlag(&a.Edit, "edit", "e", "Use an editor to modify the request body"),
			boolFlag(&a.Force, "force", "", "Force skill installation or removal"),

			// Custom: form key=value parsing
			{
				Short:       "f",
				Long:        "form",
				Args:        "KEY=VALUE",
				Description: "Send a urlencoded form body",
				IsSet:       func() bool { return len(a.Form) > 0 },
				Fn:          a.parseFormFlag,
			},

			cfgFlag("format", "", "OPTION", "Enable/disable formatting",
				func() bool { return a.Cfg.Format != core.FormatUnknown }, a.Cfg.ParseFormat).
				WithValues([]core.KeyVal[string]{
					{Key: "auto", Val: "Automatically determine whether to format"},
					{Key: "off", Val: "Disable output formatting"},
					{Key: "on", Val: "Enable output formatting"},
				}),

			stringFlag(&a.FromCurl, "from-curl", "", "COMMAND", "Execute a curl command using fetch"),
			boolFlag(&a.GRPC, "grpc", "", "Enable gRPC mode"),
			stringFlag(&a.GRPCDescribe, "grpc-describe", "", "NAME", "Describe a gRPC service, method, or message"),
			boolFlag(&a.GRPCList, "grpc-list", "", "List available gRPC services"),

			{
				Long:        "har",
				Args:        "PATH",
				Description: "Record the final exchange as HAR 1.2",
				IsSet:       func() bool { return a.HAR != "" },
				Fn: func(value string) error {
					if value == "" || value == "-" {
						return core.NewValueError("har", value, "must name a non-empty file path (standard output is not supported)", false)
					}
					a.HAR = value
					return nil
				},
			},

			cfgFlag("header", "H", "NAME:VALUE", "Set headers for the request",
				func() bool { return len(a.Cfg.Headers) > 0 }, a.Cfg.ParseHeader),

			boolFlag(&a.Help, "help", "h", "Print help"),

			cfgFlag("http", "", "VERSION", "HTTP version to use",
				func() bool { return a.Cfg.HTTP != core.HTTPDefault }, a.Cfg.ParseHTTP).
				WithValues([]core.KeyVal[string]{
					{Key: "1", Val: "HTTP/1.1"},
					{Key: "2", Val: "HTTP/2.0"},
					{Key: "3", Val: "HTTP/3.0"},
				}).
				WithAliases("http1", "http2", "http3").
				WithAliasValues(map[string]string{"http1": "1", "http2": "2", "http3": "3"}),

			ptrBoolFlag(&a.Cfg.IgnoreStatus, "ignore-status", "", "Exit code unaffected by HTTP status"),

			cfgFlag("image", "", "OPTION", "Image rendering",
				func() bool { return a.Cfg.Image != core.ImageUnknown }, a.Cfg.ParseImageSetting).
				WithValues([]core.KeyVal[string]{
					{Key: "auto", Val: "Automatically decide image display"},
					{Key: "external", Val: "Allow external image adapters"},
					{Key: "native", Val: "Only use builtin decoders"},
					{Key: "off", Val: "Disable image display"},
				}),

			ptrBoolFlag(&a.Cfg.Insecure, "insecure", "", "Accept invalid TLS certs (!)"),

			boolFlag(&a.InspectDNS, "inspect-dns", "", "Inspect DNS resolution"),
			boolFlag(&a.InspectTLS, "inspect-tls", "", "Inspect the TLS certificate chain"),

			{
				Long:        "install-skill",
				Args:        "AGENT",
				OptionalArg: true,
				Description: "Install the portable Agent Skill",
				Values:      skillAgentValues(),
				IsSet:       func() bool { return a.InstallSkill != "" },
				Fn: func(value string) error {
					parsed, err := parseSkillAgent("install-skill", value)
					if err != nil {
						return err
					}
					a.InstallSkill = parsed
					return nil
				},
			},

			// Custom: JSON body
			{
				Short:       "j",
				Long:        "json",
				Args:        "[@]VALUE",
				Description: "Send a JSON request body",
				IsSet:       func() bool { return a.jsonSet },
				Fn:          a.parseJSONFlag,
			},

			// Custom: file check + config parse
			{
				Long:        "key",
				Args:        "PATH",
				Description: "Client private key for mTLS",
				IsSet:       func() bool { return a.Cfg.KeyPath != "" },
				Fn:          a.parseKeyFlag,
			},

			cfgFlag("max-tls", "", "VERSION", "Maximum TLS version",
				func() bool { return a.Cfg.TLSMax != nil }, a.Cfg.ParseMaxTLS).
				WithValues(tlsValues()),

			stringFlag(&a.Method, "method", "m", "METHOD", "HTTP method to use").
				WithAliases("X").
				WithDefault("GET; body=POST"),

			cfgFlag("min-tls", "", "VERSION", "Minimum TLS version",
				func() bool { return a.Cfg.TLSMin != nil }, a.Cfg.ParseMinTLS).
				WithValues(tlsValues()).
				WithAliases("tls"),

			// Custom: multipart with file validation
			{
				Short:       "F",
				Long:        "multipart",
				Args:        "NAME=[@]VALUE",
				Description: "Send a multipart form body",
				IsSet:       func() bool { return len(a.Multipart) > 0 },
				Fn:          a.parseMultipartFlag,
			},

			{
				Long:        "no-encode",
				Description: "Avoid requesting gzip, br, or zstd encoding",
				IsSet:       func() bool { return a.noEncodeSet },
				Fn: func(string) error {
					if err := a.Cfg.ParseNoEncode("true"); err != nil {
						return err
					}
					if !a.compressSet {
						a.Cfg.Compress = core.CompressionOff
					}
					a.noEncodeSet = true
					return nil
				},
			},
			{
				Long:        "no-pager",
				Description: "Avoid using a pager for the output",
				IsSet:       func() bool { return a.noPagerSet },
				Fn: func(string) error {
					if err := a.Cfg.ParseNoPager("true"); err != nil {
						return err
					}
					if !a.pagerSet {
						a.Cfg.Pager = core.PagerOff
					}
					a.noPagerSet = true
					return nil
				},
			},

			stringFlag(&a.Output, "output", "o", "PATH", "Write the response body to a file"),

			Flag{
				Long:        "pager",
				Args:        "MODE",
				Description: "Pager behavior",
				IsSet:       func() bool { return a.pagerSet },
				Fn: func(value string) error {
					if err := a.Cfg.ParsePager(value); err != nil {
						return err
					}
					a.pagerSet = true
					return nil
				},
			}.
				WithValues([]core.KeyVal[string]{
					{Key: "auto", Val: "Page formatted terminal output automatically"},
					{Key: "on", Val: "Force a pager when output is suitable"},
					{Key: "off", Val: "Disable paging"},
				}),

			// Custom: proto flags with file validation
			{
				Long:        "proto-desc",
				Args:        "PATH",
				Description: "Pre-compiled descriptor set file",
				IsSet:       func() bool { return a.ProtoDesc != "" },
				Fn:          a.parseProtoDescFlag,
			},
			{
				Long:        "proto-file",
				Args:        "PATH",
				Description: "Compile .proto file(s) via protoc",
				IsSet:       func() bool { return len(a.ProtoFiles) > 0 },
				Fn:          a.parseProtoFileFlag,
			},
			{
				Long:        "proto-import",
				Args:        "PATH",
				Description: "Import path for proto compilation",
				IsSet:       func() bool { return len(a.ProtoImports) > 0 },
				Fn:          a.parseProtoImportFlag,
			},

			cfgFlag("proxy", "", "PROXY", "Configure a proxy",
				func() bool { return a.Cfg.Proxy != nil }, a.Cfg.ParseProxy),

			cfgFlag("query", "q", "KEY=VALUE", "Append query parameters to the url",
				func() bool { return len(a.Cfg.QueryParams) > 0 }, a.Cfg.ParseQuery),

			// Custom: range parsing with validation
			{
				Short:       "r",
				Long:        "range",
				Args:        "RANGE",
				Description: "Request a specific byte range",
				IsSet:       func() bool { return len(a.Range) > 0 },
				Fn:          a.parseRangeFlag,
			},

			cfgFlag("redirects", "", "NUM", "Maximum number of redirects",
				func() bool { return a.Cfg.Redirects != nil }, a.Cfg.ParseRedirects),

			boolFlag(&a.RemoteHeaderName, "remote-header-name", "J", "Use content-disposition header filename"),
			boolFlag(&a.RemoteName, "remote-name", "O", "Use URL path component as output filename").
				WithAliases("output-current-dir"),

			cfgFlag("retry", "", "NUM", "Maximum number of retries",
				func() bool { return a.Cfg.Retry != nil }, a.Cfg.ParseRetry).
				WithDefault("0"),
			cfgFlag("retry-delay", "", "SECONDS", "Initial delay between retries",
				func() bool { return a.Cfg.RetryDelay != nil }, a.Cfg.ParseRetryDelay).
				WithDefault("1"),

			Flag{
				Long:        "scope",
				Args:        "SCOPE",
				Description: "Skill installation scope",
				IsSet:       func() bool { return a.Scope != "" },
				Fn:          a.parseScopeFlag,
			}.WithValues([]core.KeyVal[string]{
				{Key: "user", Val: "Install in the user skill directory"},
				{Key: "project", Val: "Install in the current project"},
			}),

			cfgFlag("session", "S", "NAME", "Use a named session for cookies",
				func() bool { return a.Cfg.Session != nil }, a.Cfg.ParseSession),

			ptrBoolFlag(&a.Cfg.Silent, "silent", "s", "Print only errors to stderr"),
			{
				Long:        "skill",
				Description: "Print the portable Agent Skill",
				IsSet:       func() bool { return a.Skill },
				Fn: func(string) error {
					a.Skill = true
					return nil
				},
			},
			ptrBoolFlag(&a.Cfg.SortHeaders, "sort-headers", "", "Compatibility no-op for header ordering"),

			cfgFlag("timeout", "t", "SECONDS", "Timeout applied to the request",
				func() bool { return a.Cfg.Timeout != nil }, a.Cfg.ParseTimeout),

			ptrBoolFlag(&a.Cfg.Timing, "timing", "T", "Display a timing waterfall chart"),

			{
				Long:        "uninstall-skill",
				Args:        "AGENT",
				OptionalArg: true,
				Description: "Uninstall the portable Agent Skill",
				Values:      skillAgentValues(),
				IsSet:       func() bool { return a.UninstallSkill != "" },
				Fn: func(value string) error {
					parsed, err := parseSkillAgent("uninstall-skill", value)
					if err != nil {
						return err
					}
					a.UninstallSkill = parsed
					return nil
				},
			},

			stringFlag(&a.UnixSocket, "unix", "", "PATH", "Make the request over a unix socket").
				WithOS(unixOS),

			boolFlag(&a.Update, "update", "", "Update the fetch binary in place").
				WithHidden(core.NoSelfUpdate),

			// Custom: verbose increments verbosity
			{
				Short:       "v",
				Long:        "verbose",
				Description: "Verbosity of the output",
				IsSet:       func() bool { return a.Cfg.Verbosity != nil },
				Fn:          a.parseVerboseFlag,
			},

			boolFlag(&a.Version, "version", "V", "Print version"),

			Flag{
				Long:        "ws-interactive",
				Args:        "MODE",
				Description: "WebSocket prompt mode",
				IsSet:       func() bool { return a.WSInteractive != core.WSInteractiveAuto },
				Fn:          a.parseWSInteractiveFlag,
			}.WithValues([]core.KeyVal[string]{
				{Key: "auto", Val: "Use interactive prompt when attached to a terminal"},
				{Key: "on", Val: "Require interactive prompt"},
				{Key: "off", Val: "Disable interactive prompt"},
			}),

			Flag{
				Long:        "ws-message-mode",
				Args:        "MODE",
				Description: "WebSocket message mode",
				IsSet:       func() bool { return a.wsMessageModeSet },
				Fn: func(value string) error {
					a.wsMessageModeSet = true
					return a.parseWSMessageModeFlag(value)
				},
			}.WithValues([]core.KeyVal[string]{
				{Key: "auto", Val: "Detect text versus binary"},
				{Key: "text", Val: "Require UTF-8 text messages"},
				{Key: "binary", Val: "Send binary messages"},
			}),

			// Custom: XML body
			{
				Short:       "x",
				Long:        "xml",
				Args:        "[@]VALUE",
				Description: "Send an XML request body",
				IsSet:       func() bool { return a.xmlSet },
				Fn:          a.parseXMLFlag,
			},
		},
	}
	cli.Options()
	return cli
}

func tlsValues() []core.KeyVal[string] {
	return []core.KeyVal[string]{
		{Key: "1.0", Val: "TLS v1.0"},
		{Key: "1.1", Val: "TLS v1.1"},
		{Key: "1.2", Val: "TLS v1.2"},
		{Key: "1.3", Val: "TLS v1.3"},
	}
}

func (a *App) parseAWSSigv4Flag(value string) error {
	region, service, ok := core.CutTrimmed(value, "/")
	if !ok {
		const usage = "format must be <REGION/SERVICE>"
		return core.NewValueError("aws-sigv4", value, usage, false)
	}
	cfg, err := buildAWSConfig(region, service)
	if err != nil {
		return err
	}
	a.AWSSigv4 = cfg
	return nil
}

func (a *App) parseBasicFlag(value string) error {
	user, pass, ok := core.CutTrimmed(value, ":")
	if !ok {
		const usage = "format must be <USERNAME:PASSWORD>"
		return core.NewValueError("basic", value, usage, false)
	}
	a.Basic = &core.KeyVal[string]{Key: user, Val: pass}
	return nil
}

func (a *App) parseDigestFlag(value string) error {
	user, pass, ok := core.CutTrimmed(value, ":")
	if !ok {
		const usage = "format must be <USERNAME:PASSWORD>"
		return core.NewValueError("digest", value, usage, false)
	}
	a.Digest = &core.KeyVal[string]{Key: user, Val: pass}
	return nil
}

func (a *App) parseCertFlag(value string) error {
	if err := checkFileExists(value); err != nil {
		return err
	}
	return a.Cfg.ParseCert(value)
}

func (a *App) parseDataFlag(value string) error {
	r, path, err := RequestBody(value)
	if err != nil {
		return err
	}
	a.Data, a.ContentType, err = core.DetectContentType(r, path)
	if err != nil {
		return err
	}
	a.dataSet = true
	return nil
}

func (a *App) parseFormFlag(value string) error {
	key, val, _ := strings.Cut(value, "=")
	a.Form = append(a.Form, core.KeyVal[string]{Key: strings.TrimSpace(key), Val: val})
	return nil
}

func (a *App) parseJSONFlag(value string) error {
	r, _, err := RequestBody(value)
	if err != nil {
		return err
	}
	a.Data = r
	a.ContentType = "application/json"
	a.jsonSet = true
	return nil
}

func (a *App) parseKeyFlag(value string) error {
	if err := checkFileExists(value); err != nil {
		return err
	}
	return a.Cfg.ParseKey(value)
}

func (a *App) parseMultipartFlag(value string) error {
	key, val, _ := strings.Cut(value, "=")
	key = strings.TrimSpace(key)
	if strings.HasPrefix(val, "@") {
		path := val[1:]

		// Expand '~' to the home directory.
		if len(path) >= 2 && path[0] == '~' && path[1] == os.PathSeparator {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			path = home + path[1:]
			val = "@" + path
		}

		// Ensure the file exists.
		stats, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("file does not exist: '%s'", path)
			}
			return err
		}
		if stats.IsDir() {
			return fmt.Errorf("file is a directory: '%s'", path)
		}
	}
	a.Multipart = append(a.Multipart, core.KeyVal[string]{Key: key, Val: val})
	return nil
}

func (a *App) parseProtoDescFlag(value string) error {
	a.ProtoDesc = value
	return checkFileExists(value)
}

func (a *App) parseProtoFileFlag(value string) error {
	// Support comma-separated paths.
	for p := range strings.SplitSeq(value, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		err := checkFileExists(p)
		if err != nil {
			return err
		}
		a.ProtoFiles = append(a.ProtoFiles, p)
	}
	return nil
}

func (a *App) parseProtoImportFlag(value string) error {
	a.ProtoImports = append(a.ProtoImports, value)
	return checkFileExists(value)
}

func (a *App) parseRangeFlag(value string) error {
	value = strings.TrimSpace(value)
	start, end, ok := strings.Cut(value, "-")
	start = strings.TrimSpace(start)
	end = strings.TrimSpace(end)
	if !ok || (start == "" && end == "") {
		const usage = "invalid byte range"
		return core.NewValueError("range", value, usage, false)
	}
	if !isValidRangeValue(start) {
		usage := fmt.Sprintf("invalid range start '%s'", start)
		return core.NewValueError("range", value, usage, false)
	}
	if !isValidRangeValue(end) {
		usage := fmt.Sprintf("invalid range end '%s'", end)
		return core.NewValueError("range", value, usage, false)
	}
	a.Range = append(a.Range, start+"-"+end)
	return nil
}

func (a *App) parseVerboseFlag(string) error {
	if a.Cfg.Verbosity == nil {
		a.Cfg.Verbosity = new(1)
	} else {
		(*a.Cfg.Verbosity)++
	}
	return nil
}

func (a *App) parseXMLFlag(value string) error {
	r, _, err := RequestBody(value)
	if err != nil {
		return err
	}
	a.Data = r
	a.ContentType = "application/xml"
	a.xmlSet = true
	return nil
}

func (a *App) parseWSInteractiveFlag(value string) error {
	switch value {
	case "auto":
		a.WSInteractive = core.WSInteractiveAuto
	case "on":
		a.WSInteractive = core.WSInteractiveOn
	case "off":
		a.WSInteractive = core.WSInteractiveOff
	default:
		return core.NewValueError("ws-interactive", value, "must be one of [auto, on, off]", false)
	}
	return nil
}

func (a *App) parseWSMessageModeFlag(value string) error {
	switch value {
	case "auto":
		a.WSMessageMode = core.WSMessageAuto
	case "text":
		a.WSMessageMode = core.WSMessageText
	case "binary":
		a.WSMessageMode = core.WSMessageBinary
	default:
		return core.NewValueError("ws-message-mode", value, "must be one of [auto, text, binary]", false)
	}
	return nil
}

func (a *App) parseScopeFlag(value string) error {
	switch value {
	case "user", "project":
		a.Scope = value
		return nil
	default:
		return core.NewValueError("scope", value, "must be one of [user, project]", false)
	}
}

func skillAgentValues() []core.KeyVal[string] {
	return []core.KeyVal[string]{
		{Key: "auto", Val: "Choose the default Agents location"},
		{Key: "agents", Val: "Generic Agents skill directory"},
		{Key: "codex", Val: "Codex skill directory"},
		{Key: "claude", Val: "Claude skill directory"},
		{Key: "gemini", Val: "Gemini skill directory"},
		{Key: "pi", Val: "Pi skill directory"},
		{Key: "all", Val: "Install or remove all supported skill directories"},
	}
}

func parseSkillAgent(option, value string) (string, error) {
	if value == "" {
		return "auto", nil
	}
	for _, accepted := range skillAgentValues() {
		if value == accepted.Key {
			return value, nil
		}
	}
	return "", core.NewValueError(option, value, "must be one of [auto, agents, codex, claude, gemini, pi, all]", false)
}

// buildAWSConfig creates an AWS configuration from region and service.
// Credentials are loaded when the request is signed so inspection modes can
// ignore --aws-sigv4 without requiring AWS environment variables.
func buildAWSConfig(region, service string) (*aws.Config, error) {
	return &aws.Config{
		Region:  region,
		Service: service,
	}, nil
}

// parseURL normalizes a raw URL string: adds "//" when the scheme is
// omitted, rewrites ws/wss schemes to http/https, and validates the scheme.
// It returns the parsed URL, whether it was a WebSocket URL, and any error.
func parseURL(rawURL string) (*url.URL, bool, error) {
	if rawURL == "" {
		return nil, false, fmt.Errorf("empty URL provided")
	}

	// For URLs that have the scheme omitted, add two slashes so the host is
	// parsed as an authority rather than as a path or a scheme-like hostname
	// such as "localhost:3000".
	if !hasAuthorityScheme(rawURL) && rawURL[0] != '/' {
		rawURL = "//" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, false, fmt.Errorf("invalid url: %w", err)
	}

	// Lowercase the scheme, validate it, and normalize schemeless URLs now so
	// dry-run and request construction use the same absolute URL.
	var isWS bool
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "":
		if u.Host == "" {
			return nil, false, fmt.Errorf("invalid url: missing host")
		}
		if isIPLiteral(u.Hostname()) || strings.EqualFold(u.Hostname(), "localhost") {
			u.Scheme = "http"
		} else {
			u.Scheme = "https"
		}
	case "http", "https":
	case "ws":
		u.Scheme = "http"
		isWS = true
	case "wss":
		u.Scheme = "https"
		isWS = true
	default:
		return nil, false, fmt.Errorf("unsupported url scheme: %s", u.Scheme)
	}
	return u, isWS, nil
}

func isIPLiteral(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if zone := strings.LastIndexByte(host, '%'); zone > 0 {
		return net.ParseIP(host[:zone]) != nil
	}
	return false
}

func hasAuthorityScheme(raw string) bool {
	colon := strings.IndexByte(raw, ':')
	if colon <= 0 {
		return false
	}
	if delimiter := strings.IndexAny(raw, "/?#"); delimiter >= 0 && colon > delimiter {
		return false
	}
	for i := 0; i < colon; i++ {
		c := raw[i]
		if (i == 0 && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z')) ||
			(i > 0 && !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')) {
			return false
		}
	}
	return strings.HasPrefix(raw[colon+1:], "//")
}

func (a *App) hasRequestBody() bool {
	return a.Data != nil || len(a.Form) > 0 || len(a.Multipart) > 0 || a.Edit
}

func RequestBody(value string) (io.Reader, string, error) {
	switch {
	case len(value) == 0 || value[0] != '@':
		return strings.NewReader(value), "", nil
	case value == "@-":
		return os.Stdin, "", nil
	default:
		path := value[1:]
		// Expand '~' to the home directory.
		if len(path) >= 2 && path[0] == '~' && path[1] == os.PathSeparator {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, "", err
			}
			path = home + path[1:]
		}
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, "", core.FileNotExistsError(value[1:])
			}
			return nil, "", err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, "", err
		}
		if info.IsDir() {
			f.Close()
			return nil, "", fileIsDirError(value[1:])
		}
		return f, path, nil
	}
}

func checkFileExists(value string) error {
	_, err := os.Stat(value)
	if err == nil {
		return nil
	}
	if os.IsNotExist(err) {
		return core.FileNotExistsError(value)
	}
	return err
}

func isValidRangeValue(value string) bool {
	if value == "" {
		return true
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
