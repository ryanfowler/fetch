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
	DryRun           bool
	Edit             bool
	Form             []core.KeyVal[string]
	GRPC             bool
	Help             bool
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

	dataSet, jsonSet, xmlSet bool
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
			if s == "" {
				return fmt.Errorf("empty URL provided")
			}

			// For URLs that have the scheme omitted, add two
			// slashes so it can be parsed correctly.
			if !strings.Contains(s, "://") && s[0] != '/' {
				s = "//" + s
			}

			u, err := url.Parse(s)
			if err != nil {
				return fmt.Errorf("invalid url: %w", err)
			}

			// Lowercase the scheme, and validate.
			u.Scheme = strings.ToLower(u.Scheme)
			switch u.Scheme {
			case "", "http", "https":
			default:
				return fmt.Errorf("unsupported url scheme: %s", u.Scheme)
			}

			a.URL = u
			return nil
		},
		ExclusiveFlags: [][]string{
			{"aws-sigv4", "basic", "bearer"},
			{"data", "form", "json", "multipart", "xml"},
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
		Flags: []Flag{
			{
				Short:       "",
				Long:        "auto-update",
				Args:        "(ENABLED|INTERVAL)",
				IsHidden:    true,
				Description: "Enable/disable auto-updates",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.AutoUpdate != nil
				},
				Fn: func(value string) error {
					return a.Cfg.ParseAutoUpdate(value)
				},
			},
			{
				Short:       "",
				Long:        "aws-sigv4",
				Args:        "REGION/SERVICE",
				Description: "Sign the request using AWS signature V4",
				Default:     "",
				IsSet: func() bool {
					return a.AWSSigv4 != nil
				},
				Fn: func(value string) error {
					region, service, ok := cut(value, "/")
					if !ok {
						const usage = "format must be <REGION/SERVICE>"
						return core.NewValueError("aws-sigv4", value, usage, false)
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
					return nil
				},
			},
			{
				Short:       "",
				Long:        "basic",
				Args:        "USER:PASS",
				Description: "Enable HTTP basic authentication",
				Default:     "",
				IsSet: func() bool {
					return a.Basic != nil
				},
				Fn: func(value string) error {
					user, pass, ok := cut(value, ":")
					if !ok {
						const usage = "format must be <USERNAME:PASSWORD>"
						return core.NewValueError("basic", value, usage, false)
					}
					a.Basic = &core.KeyVal[string]{Key: user, Val: pass}
					return nil
				},
			},
			{
				Short:       "",
				Long:        "bearer",
				Args:        "TOKEN",
				Description: "Enable HTTP bearer authentication",
				Default:     "",
				IsSet: func() bool {
					return a.Bearer != ""
				},
				Fn: func(value string) error {
					a.Bearer = value
					return nil
				},
			},
			{
				Short:       "",
				Long:        "buildinfo",
				Args:        "",
				Description: "Print the build information",
				Default:     "",
				IsSet: func() bool {
					return a.BuildInfo
				},
				Fn: func(value string) error {
					a.BuildInfo = true
					return nil
				},
			},
			{
				Short:       "",
				Long:        "ca-cert",
				Args:        "PATH",
				Description: "CA certificate file path",
				Default:     "",
				IsSet: func() bool {
					return len(a.Cfg.CACerts) > 0
				},
				Fn: func(value string) error {
					return a.Cfg.ParseCACerts(value)
				},
			},
			{
				Short:       "",
				Long:        "cert",
				Args:        "PATH",
				Description: "Client certificate for mTLS",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.CertPath != ""
				},
				Fn: func(value string) error {
					if err := checkFileExists(value); err != nil {
						return err
					}
					return a.Cfg.ParseCert(value)
				},
			},
			{
				Short:       "",
				Long:        "color",
				Args:        "OPTION",
				Description: "Enable/disable color",
				Default:     "",
				Aliases:     []string{"colour"},
				Values: []core.KeyVal[string]{
					{
						Key: "auto",
						Val: "Automatically determine color",
					},
					{
						Key: "off",
						Val: "Disable color output",
					},
					{
						Key: "on",
						Val: "Enable color output",
					},
				},
				IsSet: func() bool {
					return a.Cfg.Color != core.ColorUnknown
				},
				Fn: func(value string) error {
					return a.Cfg.ParseColor(value)
				},
			},
			{
				Short:       "",
				Long:        "clobber",
				Args:        "",
				Description: "Overwrite existing output file",
				Default:     "",
				IsSet: func() bool {
					return a.Clobber
				},
				Fn: func(value string) error {
					a.Clobber = true
					return nil
				},
			},
			{
				Short:       "",
				Long:        "complete",
				Args:        "SHELL",
				Description: "Output shell completion",
				Default:     "",
				Values: []core.KeyVal[string]{
					{Key: "fish"},
					{Key: "zsh"},
				},
				HideValues: true,
				IsSet: func() bool {
					return a.Complete != ""
				},
				Fn: func(value string) error {
					a.Complete = value
					return nil
				},
			},
			{
				Short:       "c",
				Long:        "config",
				Args:        "PATH",
				Description: "Path to config file",
				Default:     "",
				IsSet: func() bool {
					return a.ConfigPath != ""
				},
				Fn: func(value string) error {
					a.ConfigPath = value
					return nil
				},
			},
			{
				Short:       "",
				Long:        "copy",
				Args:        "",
				Description: "Copy the response body to clipboard",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.Copy != nil
				},
				Fn: func(value string) error {
					v := true
					a.Cfg.Copy = &v
					return nil
				},
			},
			{
				Short:       "d",
				Long:        "data",
				Args:        "[@]VALUE",
				Description: "Send a request body",
				Default:     "",
				IsSet: func() bool {
					return a.dataSet
				},
				Fn: func(value string) error {
					r, path, err := requestBody(value)
					if err != nil {
						return err
					}
					a.Data, a.ContentType, err = core.DetectContentType(r, path)
					if err != nil {
						return err
					}
					a.dataSet = true
					return nil
				},
			},
			{
				Short:       "",
				Long:        "dns-server",
				Args:        "IP[:PORT]|URL",
				Description: "DNS server IP or DoH URL",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.DNSServer != nil
				},
				Fn: func(value string) error {
					return a.Cfg.ParseDNSServer(value)
				},
			},
			{
				Short:       "",
				Long:        "dry-run",
				Args:        "",
				Description: "Print out the request info and exit",
				Default:     "",
				IsSet: func() bool {
					return a.DryRun
				},
				Fn: func(value string) error {
					a.DryRun = true
					return nil
				},
			},
			{
				Short:       "e",
				Long:        "edit",
				Args:        "",
				Description: "Use an editor to modify the request body",
				Default:     "",
				IsSet: func() bool {
					return a.Edit
				},
				Fn: func(value string) error {
					a.Edit = true
					return nil
				},
			},
			{
				Short:       "f",
				Long:        "form",
				Args:        "KEY=VALUE",
				Description: "Send a urlencoded form body",
				Default:     "",
				IsSet: func() bool {
					return len(a.Form) > 0
				},
				Fn: func(value string) error {
					key, val, _ := cut(value, "=")
					a.Form = append(a.Form, core.KeyVal[string]{Key: key, Val: val})
					return nil
				},
			},
			{
				Short:       "",
				Long:        "format",
				Args:        "OPTION",
				Description: "Enable/disable formatting",
				Default:     "",
				Values: []core.KeyVal[string]{
					{
						Key: "auto",
						Val: "Automatically determine whether to format",
					},
					{
						Key: "off",
						Val: "Disable output formatting",
					},
					{
						Key: "on",
						Val: "Enable output formatting",
					},
				},
				IsSet: func() bool {
					return a.Cfg.Format != core.FormatUnknown
				},
				Fn: func(value string) error {
					return a.Cfg.ParseFormat(value)
				},
			},
			{
				Short:       "",
				Long:        "grpc",
				Args:        "",
				Description: "Enable gRPC mode",
				Default:     "",
				IsSet: func() bool {
					return a.GRPC
				},
				Fn: func(value string) error {
					a.GRPC = true
					return nil
				},
			},
			{
				Short:       "H",
				Long:        "header",
				Args:        "NAME:VALUE",
				Description: "Set headers for the request",
				Default:     "",
				IsSet: func() bool {
					return len(a.Cfg.Headers) > 0
				},
				Fn: func(value string) error {
					return a.Cfg.ParseHeader(value)
				},
			},
			{
				Short:       "h",
				Long:        "help",
				Args:        "",
				Description: "Print help",
				Default:     "",
				IsSet: func() bool {
					return a.Help
				},
				Fn: func(value string) error {
					a.Help = true
					return nil
				},
			},
			{
				Short:       "",
				Long:        "http",
				Args:        "VERSION",
				Description: "HTTP version to use",
				Default:     "",
				Values: []core.KeyVal[string]{
					{
						Key: "1",
						Val: "HTTP/1.1",
					},
					{
						Key: "2",
						Val: "HTTP/2.0",
					},
					{
						Key: "3",
						Val: "HTTP/3.0",
					},
				},
				IsSet: func() bool {
					return a.Cfg.HTTP != core.HTTPDefault
				},
				Fn: func(value string) error {
					return a.Cfg.ParseHTTP(value)
				},
			},
			{
				Short:       "",
				Long:        "ignore-status",
				Args:        "",
				Description: "Exit code unaffected by HTTP status",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.IgnoreStatus != nil
				},
				Fn: func(value string) error {
					v := true
					a.Cfg.IgnoreStatus = &v
					return nil
				},
			},
			{
				Short:       "",
				Long:        "image",
				Args:        "OPTION",
				Description: "Image rendering",
				Default:     "",
				Values: []core.KeyVal[string]{
					{
						Key: "auto",
						Val: "Automatically decide image display",
					},
					{
						Key: "native",
						Val: "Only use builtin decoders",
					},
					{
						Key: "off",
						Val: "Disable image display",
					},
				},
				IsSet: func() bool {
					return a.Cfg.Image != core.ImageUnknown
				},
				Fn: func(value string) error {
					return a.Cfg.ParseImageSetting(value)
				},
			},
			{
				Short:       "",
				Long:        "insecure",
				Args:        "",
				Description: "Accept invalid TLS certs (!)",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.Insecure != nil
				},
				Fn: func(value string) error {
					v := true
					a.Cfg.Insecure = &v
					return nil
				},
			},
			{
				Short:       "j",
				Long:        "json",
				Args:        "[@]VALUE",
				Description: "Send a JSON request body",
				Default:     "",
				IsSet: func() bool {
					return a.jsonSet
				},
				Fn: func(value string) error {
					r, _, err := requestBody(value)
					if err != nil {
						return err
					}
					a.Data = r
					a.ContentType = "application/json"
					a.jsonSet = true
					return nil
				},
			},
			{
				Short:       "",
				Long:        "key",
				Args:        "PATH",
				Description: "Client private key for mTLS",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.KeyPath != ""
				},
				Fn: func(value string) error {
					if err := checkFileExists(value); err != nil {
						return err
					}
					return a.Cfg.ParseKey(value)
				},
			},
			{
				Short:       "m",
				Long:        "method",
				Aliases:     []string{"X"},
				Args:        "METHOD",
				Description: "HTTP method to use",
				Default:     "GET",
				IsSet: func() bool {
					return a.Method != ""
				},
				Fn: func(value string) error {
					a.Method = value
					return nil
				},
			},
			{
				Short:       "F",
				Long:        "multipart",
				Args:        "NAME=[@]VALUE",
				Description: "Send a multipart form body",
				Default:     "",
				IsSet: func() bool {
					return len(a.Multipart) > 0
				},
				Fn: func(value string) error {
					key, val, _ := cut(value, "=")
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
				},
			},
			{
				Short:       "",
				Long:        "no-encode",
				Args:        "",
				Description: "Avoid requesting gzip/zstd encoding",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.NoEncode != nil
				},
				Fn: func(value string) error {
					v := true
					a.Cfg.NoEncode = &v
					return nil
				},
			},
			{
				Short:       "",
				Long:        "no-pager",
				Args:        "",
				Description: "Avoid using a pager for the output",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.NoPager != nil
				},
				Fn: func(value string) error {
					v := true
					a.Cfg.NoPager = &v
					return nil
				},
			},
			{
				Short:       "o",
				Long:        "output",
				Args:        "PATH",
				Description: "Write the response body to a file",
				Default:     "",
				IsSet: func() bool {
					return a.Output != ""
				},
				Fn: func(value string) error {
					a.Output = value
					return nil
				},
			},
			{
				Short:       "",
				Long:        "proto-desc",
				Args:        "PATH",
				Description: "Pre-compiled descriptor set file",
				Default:     "",
				IsSet: func() bool {
					return a.ProtoDesc != ""
				},
				Fn: func(value string) error {
					a.ProtoDesc = value
					return checkFileExists(value)
				},
			},
			{
				Short:       "",
				Long:        "proto-file",
				Args:        "PATH",
				Description: "Compile .proto file(s) via protoc",
				Default:     "",
				IsSet: func() bool {
					return len(a.ProtoFiles) > 0
				},
				Fn: func(value string) error {
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
				},
			},
			{
				Short:       "",
				Long:        "proto-import",
				Args:        "PATH",
				Description: "Import path for proto compilation",
				Default:     "",
				IsSet: func() bool {
					return len(a.ProtoImports) > 0
				},
				Fn: func(value string) error {
					a.ProtoImports = append(a.ProtoImports, value)
					return checkFileExists(value)
				},
			},
			{
				Short:       "",
				Long:        "proxy",
				Args:        "PROXY",
				Description: "Configure a proxy",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.Proxy != nil
				},
				Fn: func(value string) error {
					return a.Cfg.ParseProxy(value)
				},
			},
			{
				Short:       "q",
				Long:        "query",
				Args:        "KEY=VALUE",
				Description: "Append query parameters to the url",
				Default:     "",
				IsSet: func() bool {
					return len(a.Cfg.QueryParams) > 0
				},
				Fn: func(value string) error {
					return a.Cfg.ParseQuery(value)
				},
			},
			{
				Short:       "r",
				Long:        "range",
				Args:        "RANGE",
				Description: "Request a specific byte range",
				Default:     "",
				IsSet: func() bool {
					return len(a.Range) > 0
				},
				Fn: func(value string) error {
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
				},
			},
			{
				Short:       "",
				Long:        "redirects",
				Args:        "NUM",
				Description: "Maximum number of redirects",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.Redirects != nil
				},
				Fn: func(value string) error {
					return a.Cfg.ParseRedirects(value)
				},
			},
			{
				Short:       "J",
				Long:        "remote-header-name",
				Args:        "",
				Description: "Use content-disposition header filename",
				Default:     "",
				IsSet: func() bool {
					return a.RemoteHeaderName
				},
				Fn: func(value string) error {
					a.RemoteHeaderName = true
					return nil
				},
			},
			{
				Short:       "O",
				Long:        "remote-name",
				Aliases:     []string{"output-current-dir"},
				Args:        "",
				Description: "Use URL path component as output filename",
				Default:     "",
				IsSet: func() bool {
					return a.RemoteName
				},
				Fn: func(value string) error {
					a.RemoteName = true
					return nil
				},
			},
			{
				Short:       "s",
				Long:        "silent",
				Args:        "",
				Description: "Print only errors to stderr",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.Silent != nil
				},
				Fn: func(value string) error {
					v := true
					a.Cfg.Silent = &v
					return nil
				},
			},
			{
				Short:       "S",
				Long:        "session",
				Args:        "NAME",
				Description: "Use a named session for cookies",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.Session != nil
				},
				Fn: func(value string) error {
					return a.Cfg.ParseSession(value)
				},
			},
			{
				Short:       "t",
				Long:        "timeout",
				Args:        "SECONDS",
				Description: "Timeout applied to the request",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.Timeout != nil
				},
				Fn: func(value string) error {
					return a.Cfg.ParseTimeout(value)
				},
			},
			{
				Short:       "",
				Long:        "tls",
				Args:        "VERSION",
				Description: "Minimum TLS version",
				Default:     "",
				Values: []core.KeyVal[string]{
					{
						Key: "1.0",
						Val: "TLS v1.0",
					},
					{
						Key: "1.1",
						Val: "TLS v1.1",
					},
					{
						Key: "1.2",
						Val: "TLS v1.2",
					},
					{
						Key: "1.3",
						Val: "TLS v1.3",
					},
				},
				IsSet: func() bool {
					return a.Cfg.TLS != nil
				},
				Fn: func(value string) error {
					return a.Cfg.ParseTLS(value)
				},
			},
			{
				Short:       "",
				Long:        "unix",
				Args:        "PATH",
				Description: "Make the request over a unix socket",
				Default:     "",
				OS:          unixOS,
				IsSet: func() bool {
					return a.UnixSocket != ""
				},
				Fn: func(value string) error {
					a.UnixSocket = value
					return nil
				},
			},
			{
				Short:       "",
				Long:        "update",
				Args:        "",
				IsHidden:    core.NoSelfUpdate,
				Description: "Update the fetch binary in place",
				Default:     "",
				IsSet: func() bool {
					return a.Update
				},
				Fn: func(value string) error {
					a.Update = true
					return nil
				},
			},
			{
				Short:       "v",
				Long:        "verbose",
				Args:        "",
				Description: "Verbosity of the output",
				Default:     "",
				IsSet: func() bool {
					return a.Cfg.Verbosity != nil
				},
				Fn: func(value string) error {
					if a.Cfg.Verbosity == nil {
						a.Cfg.Verbosity = core.PointerTo(1)
					} else {
						(*a.Cfg.Verbosity)++
					}
					return nil
				},
			},
			{
				Short:       "V",
				Long:        "version",
				Args:        "",
				Description: "Print version",
				Default:     "",
				IsSet: func() bool {
					return a.Version
				},
				Fn: func(value string) error {
					a.Version = true
					return nil
				},
			},
			{
				Short:       "x",
				Long:        "xml",
				Args:        "[@]VALUE",
				Description: "Send an XML request body",
				Default:     "",
				IsSet: func() bool {
					return a.xmlSet
				},
				Fn: func(value string) error {
					r, _, err := requestBody(value)
					if err != nil {
						return err
					}
					a.Data = r
					a.ContentType = "application/xml"
					a.xmlSet = true
					return nil
				},
			},
		},
	}
}

func requestBody(value string) (io.Reader, string, error) {
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
			return nil, "", err
		}
		if info.IsDir() {
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

func cut(s, sep string) (string, string, bool) {
	key, val, ok := strings.Cut(s, sep)
	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)
	return key, val, ok
}

func isValidRangeValue(value string) bool {
	if value == "" {
		return true
	}
	_, err := strconv.Atoi(value)
	return err == nil
}

type MissingEnvVarError struct {
	EnvVar string
	Flag   string
}

type fileIsDirError string

func (err fileIsDirError) Error() string {
	return fmt.Sprintf("file '%s' is a directory", string(err))
}

func (err fileIsDirError) PrintTo(p *core.Printer) {
	p.WriteString("file '")
	p.Set(core.Dim)
	p.WriteString(string(err))
	p.Reset()
	p.WriteString("' is a directory")
}

func missingEnvVarErr(envVar, flag string) *MissingEnvVarError {
	return &MissingEnvVarError{
		EnvVar: envVar,
		Flag:   flag,
	}
}

func (err *MissingEnvVarError) Error() string {
	return fmt.Sprintf("missing environment variable '%s' required for option '--%s'", err.EnvVar, err.Flag)
}

func (err *MissingEnvVarError) PrintTo(p *core.Printer) {
	p.WriteString("missing environment variable '")
	p.Set(core.Yellow)
	p.WriteString(err.EnvVar)
	p.Reset()

	p.WriteString("' required for option '")
	p.Set(core.Bold)
	p.WriteString("--")
	p.WriteString(err.Flag)
	p.Reset()

	p.WriteString("'")
}
