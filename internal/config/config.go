package config

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

// Config represents the configuration options for fetch.
type Config struct {
	isFile bool

	Color        core.Color
	DNSServer    *url.URL
	Format       core.Format
	Headers      []core.KeyVal
	HTTP         core.HTTPVersion
	IgnoreStatus *bool
	Insecure     *bool
	NoEncode     *bool
	NoPager      *bool
	Proxy        *url.URL
	QueryParams  []core.KeyVal
	Redirects    *int
	Silent       *bool
	Timeout      *time.Duration
	TLS          *uint16
	Verbosity    *int
}

// Merge merges the two Configs together, with "c" taking priority.
func (c *Config) Merge(c2 *Config) {
	if c.Color == core.ColorUnknown {
		c.Color = c2.Color
	}
	if c.DNSServer == nil {
		c.DNSServer = c2.DNSServer
	}
	if c.Format == core.FormatUnknown {
		c.Format = c2.Format
	}
	if len(c2.Headers) > 0 {
		c.Headers = append(c2.Headers, c.Headers...)
	}
	if c.HTTP == core.HTTPDefault {
		c.HTTP = c2.HTTP
	}
	if c.IgnoreStatus == nil {
		c.IgnoreStatus = c2.IgnoreStatus
	}
	if c.Insecure == nil {
		c.Insecure = c2.Insecure
	}
	if c.NoEncode == nil {
		c.NoEncode = c2.NoEncode
	}
	if c.NoPager == nil {
		c.NoPager = c2.NoPager
	}
	if c.Proxy == nil {
		c.Proxy = c2.Proxy
	}
	if len(c2.QueryParams) > 0 {
		c.QueryParams = append(c2.QueryParams, c.QueryParams...)
	}
	if c.Redirects == nil {
		c.Redirects = c2.Redirects
	}
	if c.Silent == nil {
		c.Silent = c2.Silent
	}
	if c.Timeout == nil {
		c.Timeout = c2.Timeout
	}
	if c.TLS == nil {
		c.TLS = c2.TLS
	}
	if c.Verbosity == nil {
		c.Verbosity = c2.Verbosity
	}
}

// Set sets the provided key and value pair, returning any error encountered.
func (c *Config) Set(key, val string) error {
	var err error
	switch key {
	case "color":
		err = c.ParseColor(val)
	case "dns-server":
		err = c.ParseDNSServer(val)
	case "format":
		err = c.ParseFormat(val)
	case "header":
		err = c.ParseHeader(val)
	case "http":
		err = c.ParseHTTP(val)
	case "ignore-status":
		err = c.ParseIgnoreStatus(val)
	case "insecure":
		err = c.ParseInsecure(val)
	case "no-encode":
		err = c.ParseNoEncode(val)
	case "no-pager":
		err = c.ParseNoPager(val)
	case "proxy":
		err = c.ParseProxy(val)
	case "query":
		err = c.ParseQuery(val)
	case "redirects":
		err = c.ParseRedirects(val)
	case "silent":
		err = c.ParseSilent(val)
	case "timeout":
		err = c.ParseTimeout(val)
	case "tls":
		err = c.ParseTLS(val)
	case "verbosity":
		err = c.ParseVerbosity(val)
	default:
		err = fmt.Errorf("invalid option '%s'", key)
	}
	return err
}

func (c *Config) ParseColor(value string) error {
	switch value {
	case "auto":
		c.Color = core.ColorAuto
	case "off":
		c.Color = core.ColorOff
	case "on":
		c.Color = core.ColorOn
	default:
		const usage = "must be one of [auto, off, on]"
		return core.NewValueError("color", value, usage, c.isFile)
	}
	return nil
}

func (c *Config) ParseDNSServer(value string) error {
	if strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://") {
		u, err := url.Parse(value)
		if err != nil {
			return core.NewValueError("dns-server", value, "unable to parse DoH URL", c.isFile)
		}
		c.DNSServer = u
		return nil
	}

	port := "53"
	host := value
	const usage = "must be in the format <IP[:PORT]>"
	if colons := strings.Count(value, ":"); colons == 1 || (colons > 1 && strings.HasPrefix(value, "[")) {
		var err error
		host, port, err = net.SplitHostPort(value)
		if err != nil {
			return core.NewValueError("dns-server", value, usage, c.isFile)
		}
	}
	if net.ParseIP(host) == nil {
		return core.NewValueError("dns-server", value, usage, c.isFile)
	}

	u := url.URL{Host: net.JoinHostPort(host, port)}
	c.DNSServer = &u
	return nil
}

func (c *Config) ParseFormat(value string) error {
	switch value {
	case "auto":
		c.Format = core.FormatAuto
	case "off":
		c.Format = core.FormatOff
	case "on":
		c.Format = core.FormatOn
	default:
		const usage = "must be one of [auto, off, on]"
		return core.NewValueError("format", value, usage, c.isFile)
	}
	return nil
}

func (c *Config) ParseHeader(value string) error {
	key, val, _ := cut(value, ":")
	c.Headers = append(c.Headers, core.KeyVal{Key: key, Val: val})
	return nil

}

func (c *Config) ParseHTTP(value string) error {
	switch value {
	case "1":
		c.HTTP = core.HTTP1
	case "2":
		c.HTTP = core.HTTP2
	default:
		const usage = "must be one of [1, 2]"
		return core.NewValueError("http", value, usage, c.isFile)
	}
	return nil
}

func (c *Config) ParseIgnoreStatus(value string) error {
	v, err := strconv.ParseBool(value)
	if err != nil {
		return core.NewValueError("ignore-status", value, "must be a boolean", c.isFile)
	}
	c.IgnoreStatus = &v
	return nil
}

func (c *Config) ParseInsecure(value string) error {
	v, err := strconv.ParseBool(value)
	if err != nil {
		return core.NewValueError("insecure", value, "must be a boolean", c.isFile)
	}
	c.Insecure = &v
	return nil
}

func (c *Config) ParseNoEncode(value string) error {
	v, err := strconv.ParseBool(value)
	if err != nil {
		return core.NewValueError("no-encode", value, "must be a boolean", c.isFile)
	}
	c.NoEncode = &v
	return nil
}

func (c *Config) ParseNoPager(value string) error {
	v, err := strconv.ParseBool(value)
	if err != nil {
		return core.NewValueError("no-pager", value, "must be a boolean", c.isFile)
	}
	c.NoPager = &v
	return nil
}

func (c *Config) ParseProxy(value string) error {
	proxy, err := url.Parse(value)
	if err != nil {
		return core.NewValueError("proxy", value, err.Error(), c.isFile)
	}
	c.Proxy = proxy
	return nil
}

func (c *Config) ParseQuery(value string) error {
	key, val, _ := cut(value, "=")
	c.QueryParams = append(c.QueryParams, core.KeyVal{Key: key, Val: val})
	return nil
}

func (c *Config) ParseRedirects(value string) error {
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		const usage = "must be a positive integer"
		return core.NewValueError("redirects", value, usage, c.isFile)
	}
	c.Redirects = &n
	return nil
}

func (c *Config) ParseSilent(value string) error {
	v, err := strconv.ParseBool(value)
	if err != nil {
		return core.NewValueError("silent", value, "must be a boolean", c.isFile)
	}
	c.Silent = &v
	return nil
}

func (c *Config) ParseTimeout(value string) error {
	secs, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return core.NewValueError("timeout", value, "must be a valid number", c.isFile)
	}
	c.Timeout = core.PointerTo(time.Duration(float64(time.Second) * secs))
	return nil
}

func (c *Config) ParseTLS(value string) error {
	var version uint16
	switch value {
	case "1.0":
		version = tls.VersionTLS10
	case "1.1":
		version = tls.VersionTLS11
	case "1.2":
		version = tls.VersionTLS12
	case "1.3":
		version = tls.VersionTLS13
	default:
		const usage = "must be one of [1.0, 1.1, 1.2, 1.3]"
		return core.NewValueError("tls", value, usage, c.isFile)
	}
	c.TLS = &version
	return nil

}

func (c *Config) ParseVerbosity(value string) error {
	v, err := strconv.Atoi(value)
	if err != nil || v < 0 {
		return core.NewValueError("verbosity", value, "must be a valid integer", c.isFile)
	}
	c.Verbosity = &v
	return nil
}

func cut(s, sep string) (string, string, bool) {
	key, val, ok := strings.Cut(s, sep)
	key, val = strings.TrimSpace(key), strings.TrimSpace(val)
	return key, val, ok
}
