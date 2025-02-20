package cli

import (
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
	"github.com/ryanfowler/fetch/internal/printer"
	"github.com/ryanfowler/fetch/internal/vars"
)

type App struct {
	URL string

	AWSSigv4    *aws.Config
	Basic       *vars.KeyVal
	Bearer      string
	Color       printer.Color
	Data        io.Reader
	DryRun      bool
	Edit        bool
	Form        []vars.KeyVal
	Headers     []vars.KeyVal
	Help        bool
	HTTP        client.HTTPVersion
	Insecure    bool
	JSON        bool
	Method      string
	Multipart   []vars.KeyVal
	NoEncode    bool
	NoFormat    bool
	NoPager     bool
	Output      string
	Proxy       *url.URL
	QueryParams []vars.KeyVal
	Silent      bool
	Timeout     time.Duration
	Update      bool
	Verbose     int
	Version     bool
	XML         bool
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

func (a *App) CLI() *CLI {
	return &CLI{
		Description: "fetch is a modern HTTP(S) client for the command line",
		Args: []Arguments{
			{Name: "URL", Description: "The URL to make a request to"},
		},
		ArgFn: func(s string) error {
			if a.URL != "" {
				return fmt.Errorf("unexpected argument: %q", s)
			}
			a.URL = s
			return nil
		},
		Flags: []Flag{
			{
				Short:       "",
				Long:        "aws-sigv4",
				Args:        "REGION/SERVICE",
				Description: "Sign the request using AWS signature V4",
				Default:     "",
				Fn: func(value string) error {
					region, service, ok := strings.Cut(value, "/")
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
				Fn: func(value string) error {
					user, pass, ok := strings.Cut(value, ":")
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
				Fn: func(value string) error {
					a.Bearer = value
					return nil
				},
			},
			{
				Short:       "",
				Long:        "color",
				Args:        "CONFIG",
				Description: "Set color config",
				Default:     "auto",
				Values:      []string{"auto", "never", "always"},
				Fn: func(value string) error {
					switch value {
					case "auto":
						a.Color = printer.ColorAuto
					case "never":
						a.Color = printer.ColorNever
					case "always":
						a.Color = printer.ColorAlways
					default:
						return fmt.Errorf("invalid vlaue for color: %q", value)
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
				Fn: func(value string) error {
					key, val, _ := strings.Cut(value, "=")
					a.Form = append(a.Form, vars.KeyVal{Key: key, Val: val})
					return nil
				},
			},
			{
				Short:       "H",
				Long:        "header",
				Args:        "NAME:VALUE",
				Description: "Set headers for the request",
				Default:     "",
				Fn: func(value string) error {
					key, val, _ := strings.Cut(value, ":")
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
				Fn: func(value string) error {
					a.Help = true
					return nil
				},
			},
			{
				Short:       "",
				Long:        "http",
				Args:        "VERSION",
				Description: "Force the use of an HTTP version",
				Default:     "",
				Values:      []string{"1", "2"},
				Fn: func(value string) error {
					switch value {
					case "1", "1.1":
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
				Long:        "insecure",
				Args:        "",
				Description: "Accept invalid TLS certificates - DANGER!",
				Default:     "",
				Fn: func(value string) error {
					a.Insecure = true
					return nil
				},
			},
			{
				Short:       "j",
				Long:        "json",
				Args:        "",
				Description: "Set the request content-type to application/json",
				Default:     "",
				Fn: func(value string) error {
					a.JSON = true
					return nil
				},
			},
			{
				Short:       "m",
				Long:        "method",
				Args:        "METHOD",
				Description: "HTTP method to use",
				Default:     "GET",
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
				Fn: func(value string) error {
					key, val, _ := strings.Cut(value, "=")
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
				Fn: func(value string) error {
					a.NoEncode = true
					return nil
				},
			},
			{
				Short:       "",
				Long:        "no-format",
				Args:        "",
				Description: "Avoid formatting the output",
				Default:     "",
				Fn: func(value string) error {
					a.NoFormat = true
					return nil
				},
			},
			{
				Short:       "",
				Long:        "no-pager",
				Args:        "",
				Description: "Avoid using a pager for the response body",
				Default:     "",
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
				Fn: func(value string) error {
					key, val, _ := strings.Cut(value, "=")
					a.QueryParams = append(a.QueryParams, vars.KeyVal{Key: key, Val: val})
					return nil
				},
			},
			{
				Short:       "s",
				Long:        "silent",
				Args:        "",
				Description: "Avoid printing anything to stderr",
				Default:     "",
				Fn: func(value string) error {
					a.Silent = true
					return nil
				},
			},
			{
				Short:       "t",
				Long:        "timeout",
				Args:        "SECONDS",
				Description: "Timeout in seconds applied to the entire request",
				Default:     "",
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
				Long:        "update",
				Args:        "",
				Description: "Update the fetch binary in place",
				Default:     "",
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
				Fn: func(value string) error {
					a.Version = true
					return nil
				},
			},
			{
				Short:       "x",
				Long:        "xml",
				Args:        "",
				Description: "Set the request content-type to application/xml",
				Default:     "",
				Fn: func(value string) error {
					a.XML = true
					return nil
				},
			},
		},
	}
}
