package cli

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/aws"
	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/fetch"
	"github.com/ryanfowler/fetch/internal/printer"
	"github.com/ryanfowler/fetch/internal/vars"
)

type App struct {
	URL *url.URL

	AWSSigv4     *aws.Config
	Basic        *vars.KeyVal
	Bearer       string
	Color        printer.Color
	Data         io.Reader
	DryRun       bool
	Edit         bool
	Form         []vars.KeyVal
	Format       fetch.Format
	Headers      []vars.KeyVal
	Help         bool
	HTTP         client.HTTPVersion
	IgnoreStatus bool
	Insecure     bool
	JSON         bool
	Method       string
	Multipart    []vars.KeyVal
	NoEncode     bool
	NoPager      bool
	Output       string
	Proxy        *url.URL
	QueryParams  []vars.KeyVal
	Silent       bool
	Timeout      time.Duration
	TLS          uint16
	Update       bool
	Verbose      int
	Version      bool
	XML          bool
}

func NewApp() *App {
	var app App
	for _, flag := range app.CLI().Flags {
		if flag.Default != "" {
			err := flag.Fn(flag.Default)
			if err != nil {
				msg := fmt.Sprintf("invalid default for %q: %q", flag.Long, flag.Default)
				panic(msg)
			}
		}
	}
	return &app
}

func (a *App) PrintHelp(p *printer.Printer) {
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

			u, err := url.Parse(s)
			if err != nil {
				return fmt.Errorf("invalid url: %w", err)
			}
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
			{"data", "form", "multipart"},
			{"form", "json", "multipart", "xml"},
		},
		Flags: []Flag{
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
						return errors.New("aws-sigv4 must be provided as REGION/SERVICE")
					}

					accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
					if accessKey == "" {
						return errors.New("AWS_ACCESS_KEY_ID env var must be provided")
					}
					secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
					if secretKey == "" {
						return errors.New("AWS_SECRET_ACCESS_KEY env var must be provided")
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
						return fmt.Errorf("invalid format for basic auth: %q", value)
					}
					a.Basic = &vars.KeyVal{Key: user, Val: pass}
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
				Long:        "color",
				Args:        "OPTION",
				Description: "Enable/disable color",
				Default:     "",
				Values:      []string{"auto", "off", "on"},
				IsSet: func() bool {
					return a.Color != printer.ColorUnknown
				},
				Fn: func(value string) error {
					switch value {
					case "auto":
						a.Color = printer.ColorAuto
					case "off":
						a.Color = printer.ColorOff
					case "on":
						a.Color = printer.ColorOn
					default:
						return fmt.Errorf("invalid value for color: %q", value)
					}
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
					switch {
					case value == "":
						return errors.New("body value must be provided")
					case value[0] != '@':
						a.Data = strings.NewReader(value)
					case value == "@":
						a.Data = os.Stdin
					default:
						f, err := os.Open(value[1:])
						if err != nil {
							return err
						}
						info, err := f.Stat()
						if err != nil {
							return err
						}
						if info.IsDir() {
							return fmt.Errorf("file %q is a directory", value[1:])
						}
						a.Data = f
					}
					return nil
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
					a.Form = append(a.Form, vars.KeyVal{Key: key, Val: val})
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
					return a.Format != fetch.FormatUnknown
				},
				Fn: func(value string) error {
					switch value {
					case "auto":
						a.Format = fetch.FormatAuto
					case "off":
						a.Format = fetch.FormatOff
					case "on":
						a.Format = fetch.FormatOn
					default:
						return fmt.Errorf("invalid value for format: %q", value)
					}
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
					return len(a.Headers) > 0
				},
				Fn: func(value string) error {
					key, val, _ := cut(value, ":")
					a.Headers = append(a.Headers, vars.KeyVal{Key: key, Val: val})
					return nil
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
					return a.HTTP != client.HTTPDefault
				},
				Fn: func(value string) error {
					switch value {
					case "1":
						a.HTTP = client.HTTP1
					case "2":
						a.HTTP = client.HTTP2
					default:
						return fmt.Errorf("invalid http version: %q", value)
					}
					return nil
				},
			},
			{
				Short:       "",
				Long:        "ignore-status",
				Args:        "",
				Description: "Exit code unaffected by HTTP status",
				Default:     "",
				IsSet: func() bool {
					return a.IgnoreStatus
				},
				Fn: func(value string) error {
					a.IgnoreStatus = true
					return nil
				},
			},
			{
				Short:       "",
				Long:        "insecure",
				Args:        "",
				Description: "Accept invalid TLS certificates - DANGER!",
				Default:     "",
				IsSet: func() bool {
					return a.Insecure
				},
				Fn: func(value string) error {
					a.Insecure = true
					return nil
				},
			},
			{
				Short:       "j",
				Long:        "json",
				Args:        "",
				Description: "Set the content-type to application/json",
				Default:     "",
				IsSet: func() bool {
					return a.JSON
				},
				Fn: func(value string) error {
					a.JSON = true
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
					return a.Method != "GET"
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
							return err
						}
						if stats.IsDir() {
							return fmt.Errorf("multipart file is a directory: %q", val)
						}
					}
					a.Multipart = append(a.Multipart, vars.KeyVal{Key: key, Val: val})
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
					return a.NoEncode
				},
				Fn: func(value string) error {
					a.NoEncode = true
					return nil
				},
			},
			{
				Short:       "",
				Long:        "no-pager",
				Args:        "",
				Description: "Avoid using a pager for the response body",
				Default:     "",
				IsSet: func() bool {
					return a.NoPager
				},
				Fn: func(value string) error {
					a.NoPager = true
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
					return a.Proxy != nil
				},
				Fn: func(value string) error {
					proxy, err := url.Parse(value)
					if err != nil {
						return fmt.Errorf("invalid proxy url: %q", value)
					}
					a.Proxy = proxy
					return nil
				},
			},
			{
				Short:       "q",
				Long:        "query",
				Args:        "KEY=VALUE",
				Description: "Append query parameters to the url",
				Default:     "",
				IsSet: func() bool {
					return len(a.QueryParams) > 0
				},
				Fn: func(value string) error {
					key, val, _ := cut(value, "=")
					a.QueryParams = append(a.QueryParams, vars.KeyVal{Key: key, Val: val})
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
					return a.Silent
				},
				Fn: func(value string) error {
					a.Silent = true
					return nil
				},
			},
			{
				Short:       "t",
				Long:        "timeout",
				Args:        "SECONDS",
				Description: "Timeout in seconds applied to the request",
				Default:     "",
				IsSet: func() bool {
					return a.Timeout != 0
				},
				Fn: func(value string) error {
					secs, err := strconv.ParseFloat(value, 64)
					if err != nil {
						return fmt.Errorf("invalid value for timeout: %q", value)
					}

					a.Timeout = time.Duration(float64(time.Second) * secs)
					return nil
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
					return a.TLS != 0
				},
				Fn: func(value string) error {
					switch value {
					case "1.0":
						a.TLS = tls.VersionTLS10
					case "1.1":
						a.TLS = tls.VersionTLS11
					case "1.2":
						a.TLS = tls.VersionTLS12
					case "1.3":
						a.TLS = tls.VersionTLS13
					default:
						return fmt.Errorf("invalid value for tls: %q", value)
					}
					return nil
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
					return a.Verbose > 0
				},
				Fn: func(value string) error {
					a.Verbose += 1
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
				Args:        "",
				Description: "Set the content-type to application/xml",
				Default:     "",
				IsSet: func() bool {
					return a.XML
				},
				Fn: func(value string) error {
					a.XML = true
					return nil
				},
			},
		},
	}
}

func cut(s, sep string) (string, string, bool) {
	key, val, ok := strings.Cut(s, sep)
	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)
	return key, val, ok
}
