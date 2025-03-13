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
	URL *url.URL

	Cfg config.Config

	AWSSigv4   *aws.Config
	Basic      *core.KeyVal
	Bearer     string
	BuildInfo  bool
	ConfigPath string
	Data       io.Reader
	DryRun     bool
	Edit       bool
	Form       []core.KeyVal
	Help       bool
	JSON       io.Reader
	Method     string
	Multipart  []core.KeyVal
	Output     string
	Range      []string
	Update     bool
	Version    bool
	XML        io.Reader
}

func (a *App) PrintHelp(p *core.Printer) {
	printHelp(a.CLI(), p)
}

func (a *App) CLI() *CLI {
	return &CLI{
		Description: "fetch is a modern HTTP(S) client for the command line",
		Args: []Arguments{
			{Name: "URL", Description: "The URL to make a request to"},
		},
		ArgFn: func(s string) error {
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
					a.Basic = &core.KeyVal{Key: user, Val: pass}
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
				Long:        "color",
				Args:        "OPTION",
				Description: "Enable/disable color",
				Default:     "",
				Values:      []string{"auto", "off", "on"},
				IsSet: func() bool {
					return a.Cfg.Color != core.ColorUnknown
				},
				Fn: func(value string) error {
					return a.Cfg.ParseColor(value)
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
				Short:       "d",
				Long:        "data",
				Args:        "[@]VALUE",
				Description: "Send a request body",
				Default:     "",
				IsSet: func() bool {
					return a.Data != nil
				},
				Fn: func(value string) error {
					r, err := requestBody(value)
					if err != nil {
						return err
					}
					a.Data = r
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
					a.Form = append(a.Form, core.KeyVal{Key: key, Val: val})
					return nil
				},
			},
			{
				Short:       "",
				Long:        "format",
				Args:        "OPTION",
				Description: "Enable/disable formatting",
				Default:     "",
				Values:      []string{"auto", "off", "on"},
				IsSet: func() bool {
					return a.Cfg.Format != core.FormatUnknown
				},
				Fn: func(value string) error {
					return a.Cfg.ParseFormat(value)
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
				Description: "Highest allowed HTTP version",
				Default:     "",
				Values:      []string{"1", "2"},
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
					return a.JSON != nil
				},
				Fn: func(value string) error {
					r, err := requestBody(value)
					if err != nil {
						return err
					}
					a.JSON = r
					return nil
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
						stats, err := os.Stat(val[1:])
						if err != nil {
							if os.IsNotExist(err) {
								return fmt.Errorf("file does not exist: '%s'", val[1:])
							}
							return err
						}
						if stats.IsDir() {
							return fmt.Errorf("file is a directory: '%s'", val[1:])
						}
					}
					a.Multipart = append(a.Multipart, core.KeyVal{Key: key, Val: val})
					return nil
				},
			},
			{
				Short:       "",
				Long:        "no-encode",
				Args:        "",
				Description: "Avoid requesting gzip encoding",
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
				Args:        "FILE",
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
				Values:      []string{"1.0", "1.1", "1.2", "1.3"},
				IsSet: func() bool {
					return a.Cfg.TLS != nil
				},
				Fn: func(value string) error {
					return a.Cfg.ParseTLS(value)
				},
			},
			{
				Short:       "",
				Long:        "update",
				Args:        "",
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
					return a.XML != nil
				},
				Fn: func(value string) error {
					r, err := requestBody(value)
					if err != nil {
						return err
					}
					a.XML = r
					return nil
				},
			},
		},
	}
}

func requestBody(value string) (io.Reader, error) {
	switch {
	case len(value) == 0 || value[0] != '@':
		return strings.NewReader(value), nil
	case value == "@-":
		return os.Stdin, nil
	default:
		f, err := os.Open(value[1:])
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fileNotExistsError(value[1:])
			}
			return nil, err
		}
		info, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			return nil, fileIsDirError(value[1:])
		}
		return f, nil
	}
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

type fileNotExistsError string

func (err fileNotExistsError) Error() string {
	return fmt.Sprintf("file '%s' does not exist", string(err))
}

func (err fileNotExistsError) PrintTo(p *core.Printer) {
	p.WriteString("file '")
	p.Set(core.Dim)
	p.WriteString(string(err))
	p.Reset()
	p.WriteString("' does not exist")
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
