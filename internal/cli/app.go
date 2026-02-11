package cli

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/config"
	"github.com/ryanfowler/fetch/internal/core"
)

// App represents the full configuration for a fetch invocation.
type App struct {
	URL       *url.URL
	ExtraArgs []string

	Cfg config.Config

	AWSSigv4         *aws.Config
	Basic            *core.KeyVal[string]
	Bearer           string
	BuildInfo        bool
	Clobber          bool
	Complete         string
	ConfigPath       string
	ContentType      string
	Data             io.Reader
	Discard          bool
	DryRun           bool
	Edit             bool
	Form             []core.KeyVal[string]
	FromCurl         string
	GRPC             bool
	Help             bool
	InspectTLS       bool
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

	dataSet bool
	jsonSet bool
	xmlSet  bool
}

func (a *App) PrintHelp(p *core.Printer) {
	printHelp(a.CLI(), p)
}

func (a *App) CLI() *CLI {
	var extraArgs bool
	return &CLI{
		Description: "fetch is a modern HTTP(S) client for the command line",
		Args: []Arguments{
			{Name: "URL", Description: "The URL to make a request to"},
		},
		ArgFn: func(s string) error {
			// Append extra args, if necessary.
			if extraArgs {
				a.ExtraArgs = append(a.ExtraArgs, s)
				return nil
			}
			if s == "--" {
				extraArgs = true
				return nil
			}

			// Otherwise, parse the provided URL.
			if a.URL != nil {
				return fmt.Errorf("unexpected argument: %q", s)
			}
			u, isWS, err := parseURL(s)
			if err != nil {
				return err
			}
			a.URL = u
			a.WS = a.WS || isWS
			return nil
		},
		ExclusiveFlags: [][]string{
			{"aws-sigv4", "basic", "bearer"},
			{"data", "form", "json", "multipart", "xml"},
			{"discard", "copy"},
			{"discard", "output"},
			{"discard", "remote-name"},
			{"output", "remote-name"},
			{"proto-file", "proto-desc"},
		},
		RequiredFlags: []core.KeyVal[[]string]{
			{Key: "key", Val: []string{"cert"}},
			{Key: "proto-desc", Val: []string{"grpc"}},
			{Key: "proto-file", Val: []string{"grpc"}},
			{Key: "proto-import", Val: []string{"proto-file"}},
			{Key: "remote-header-name", Val: []string{"remote-name"}},
		},
		SchemeExclusiveFlags: map[string][]string{
			"ws":  {"discard", "grpc", "form", "multipart", "xml", "edit"},
			"wss": {"discard", "grpc", "form", "multipart", "xml", "edit"},
		},
		FromCurlExclusiveFlags: []string{
			"method", "header", "data", "json", "xml",
			"form", "multipart", "basic", "bearer", "aws-sigv4",
			"output", "remote-name", "remote-header-name",
			"range", "unix", "timeout", "connect-timeout",
			"redirects", "proxy", "insecure", "tls", "http",
			"cert", "key", "ca-cert", "dns-server",
			"retry", "retry-delay", "grpc", "query",
		},
		Flags: []Flag{
			// cfgFlag: delegates to config parser
			cfgFlag("auto-update", "", "(ENABLED|INTERVAL)", "Enable/disable auto-updates",
				func() bool { return a.Cfg.AutoUpdate != nil }, a.Cfg.ParseAutoUpdate).
				WithHidden(true),

			// Custom: AWS signature V4 with env var lookups
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
				IsSet:       func() bool { return a.dataSet },
				Fn:          a.parseDataFlag,
			},

			boolFlag(&a.Discard, "discard", "", "Discard the response body"),

			cfgFlag("dns-server", "", "IP[:PORT]|URL", "DNS server IP or DoH URL",
				func() bool { return a.Cfg.DNSServer != nil }, a.Cfg.ParseDNSServer),

			boolFlag(&a.DryRun, "dry-run", "", "Print out the request info and exit"),
			boolFlag(&a.Edit, "edit", "e", "Use an editor to modify the request body"),

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

			cfgFlag("header", "H", "NAME:VALUE", "Set headers for the request",
				func() bool { return len(a.Cfg.Headers) > 0 }, a.Cfg.ParseHeader),

			boolFlag(&a.Help, "help", "h", "Print help"),

			cfgFlag("http", "", "VERSION", "HTTP version to use",
				func() bool { return a.Cfg.HTTP != core.HTTPDefault }, a.Cfg.ParseHTTP).
				WithValues([]core.KeyVal[string]{
					{Key: "1", Val: "HTTP/1.1"},
					{Key: "2", Val: "HTTP/2.0"},
					{Key: "3", Val: "HTTP/3.0"},
				}),

			ptrBoolFlag(&a.Cfg.IgnoreStatus, "ignore-status", "", "Exit code unaffected by HTTP status"),

			cfgFlag("image", "", "OPTION", "Image rendering",
				func() bool { return a.Cfg.Image != core.ImageUnknown }, a.Cfg.ParseImageSetting).
				WithValues([]core.KeyVal[string]{
					{Key: "auto", Val: "Automatically decide image display"},
					{Key: "native", Val: "Only use builtin decoders"},
					{Key: "off", Val: "Disable image display"},
				}),

			ptrBoolFlag(&a.Cfg.Insecure, "insecure", "", "Accept invalid TLS certs (!)"),
			boolFlag(&a.InspectTLS, "inspect-tls", "", "Inspect the TLS certificate chain"),

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

			stringFlag(&a.Method, "method", "m", "METHOD", "HTTP method to use").
				WithAliases("X").
				WithDefault("GET"),

			// Custom: multipart with file validation
			{
				Short:       "F",
				Long:        "multipart",
				Args:        "NAME=[@]VALUE",
				Description: "Send a multipart form body",
				IsSet:       func() bool { return len(a.Multipart) > 0 },
				Fn:          a.parseMultipartFlag,
			},

			ptrBoolFlag(&a.Cfg.NoEncode, "no-encode", "", "Avoid requesting gzip/zstd encoding"),
			ptrBoolFlag(&a.Cfg.NoPager, "no-pager", "", "Avoid using a pager for the output"),
			stringFlag(&a.Output, "output", "o", "PATH", "Write the response body to a file"),

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

			cfgFlag("session", "S", "NAME", "Use a named session for cookies",
				func() bool { return a.Cfg.Session != nil }, a.Cfg.ParseSession),

			ptrBoolFlag(&a.Cfg.Silent, "silent", "s", "Print only errors to stderr"),

			cfgFlag("timeout", "t", "SECONDS", "Timeout applied to the request",
				func() bool { return a.Cfg.Timeout != nil }, a.Cfg.ParseTimeout),

			ptrBoolFlag(&a.Cfg.Timing, "timing", "T", "Display a timing waterfall chart"),

			cfgFlag("tls", "", "VERSION", "Minimum TLS version",
				func() bool { return a.Cfg.TLS != nil }, a.Cfg.ParseTLS).
				WithValues([]core.KeyVal[string]{
					{Key: "1.0", Val: "TLS v1.0"},
					{Key: "1.1", Val: "TLS v1.1"},
					{Key: "1.2", Val: "TLS v1.2"},
					{Key: "1.3", Val: "TLS v1.3"},
				}),

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
	key, val, _ := core.CutTrimmed(value, "=")
	a.Form = append(a.Form, core.KeyVal[string]{Key: key, Val: val})
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
	key, val, _ := core.CutTrimmed(value, "=")
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
		a.Cfg.Verbosity = core.PointerTo(1)
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

// buildAWSConfig creates an AWS configuration from region and service,
// reading credentials from environment variables.
func buildAWSConfig(region, service string) (*aws.Config, error) {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	if accessKey == "" {
		return nil, missingEnvVarErr("AWS_ACCESS_KEY_ID", "aws-sigv4")
	}
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if secretKey == "" {
		return nil, missingEnvVarErr("AWS_SECRET_ACCESS_KEY", "aws-sigv4")
	}
	return &aws.Config{
		Region:    region,
		Service:   service,
		AccessKey: accessKey,
		SecretKey: secretKey,
	}, nil
}

// parseURL normalizes a raw URL string: adds "//" when the scheme is
// omitted, rewrites ws/wss schemes to http/https, and validates the scheme.
// It returns the parsed URL, whether it was a WebSocket URL, and any error.
func parseURL(rawURL string) (*url.URL, bool, error) {
	if rawURL == "" {
		return nil, false, fmt.Errorf("empty URL provided")
	}

	// For URLs that have the scheme omitted, add two
	// slashes so it can be parsed correctly.
	if !strings.Contains(rawURL, "://") && rawURL[0] != '/' {
		rawURL = "//" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, false, fmt.Errorf("invalid url: %w", err)
	}

	// Lowercase the scheme, and validate.
	var isWS bool
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "", "http", "https":
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
	_, err := strconv.Atoi(value)
	return err == nil
}
