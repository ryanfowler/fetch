package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/session"
)

// Config represents the configuration options for fetch.
type Config struct {
	isFile bool

	AutoUpdate     *time.Duration
	CACerts        []*x509.Certificate
	CertData       []byte
	CertPath       string
	Color          core.Color
	ConnectTimeout *time.Duration
	Copy           *bool
	DNSServer      *url.URL
	Format         core.Format
	Headers        []core.KeyVal[string]
	HTTP           core.HTTPVersion
	IgnoreStatus   *bool
	Image          core.ImageSetting
	Insecure       *bool
	KeyData        []byte
	KeyPath        string
	NoEncode       *bool
	NoPager        *bool
	Proxy          *url.URL
	QueryParams    []core.KeyVal[string]
	Redirects      *int
	Retry          *int
	RetryDelay     *time.Duration
	Session        *string
	Silent         *bool
	Timeout        *time.Duration
	Timing         *bool
	TLS            *uint16
	Verbosity      *int
}

// Merge merges the two Configs together, with "c" taking priority.
func (c *Config) Merge(c2 *Config) {
	if c.AutoUpdate == nil {
		c.AutoUpdate = c2.AutoUpdate
	}
	if len(c2.CACerts) > 0 {
		c.CACerts = append(c2.CACerts, c.CACerts...)
	}
	if c.CertPath == "" && c.CertData == nil {
		c.CertData = c2.CertData
		c.CertPath = c2.CertPath
	}
	if c.Color == core.ColorUnknown {
		c.Color = c2.Color
	}
	if c.ConnectTimeout == nil {
		c.ConnectTimeout = c2.ConnectTimeout
	}
	if c.Copy == nil {
		c.Copy = c2.Copy
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
	if c.Image == core.ImageUnknown {
		c.Image = c2.Image
	}
	if c.Insecure == nil {
		c.Insecure = c2.Insecure
	}
	if c.KeyPath == "" && c.KeyData == nil {
		c.KeyData = c2.KeyData
		c.KeyPath = c2.KeyPath
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
	if c.Retry == nil {
		c.Retry = c2.Retry
	}
	if c.RetryDelay == nil {
		c.RetryDelay = c2.RetryDelay
	}
	if c.Session == nil {
		c.Session = c2.Session
	}
	if c.Silent == nil {
		c.Silent = c2.Silent
	}
	if c.Timeout == nil {
		c.Timeout = c2.Timeout
	}
	if c.Timing == nil {
		c.Timing = c2.Timing
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
	case "auto-update":
		err = c.ParseAutoUpdate(val)
	case "ca-cert":
		err = c.ParseCACerts(val)
	case "cert":
		err = c.ParseCert(val)
	case "color", "colour":
		err = c.ParseColor(val)
	case "connect-timeout":
		err = c.ParseConnectTimeout(val)
	case "copy":
		err = c.ParseCopy(val)
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
	case "image":
		err = c.ParseImageSetting(val)
	case "insecure":
		err = c.ParseInsecure(val)
	case "key":
		err = c.ParseKey(val)
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
	case "retry":
		err = c.ParseRetry(val)
	case "retry-delay":
		err = c.ParseRetryDelay(val)
	case "session":
		err = c.ParseSession(val)
	case "silent":
		err = c.ParseSilent(val)
	case "timeout":
		err = c.ParseTimeout(val)
	case "timing":
		err = c.ParseTiming(val)
	case "tls":
		err = c.ParseTLS(val)
	case "verbosity":
		err = c.ParseVerbosity(val)
	default:
		err = invalidOptionError(key)
	}
	return err
}

func (c *Config) ParseAutoUpdate(value string) error {
	v, err := strconv.ParseBool(value)
	if err == nil {
		if v {
			c.AutoUpdate = core.PointerTo(24 * time.Hour)
		} else {
			c.AutoUpdate = core.PointerTo(time.Duration(-1))
		}
		return nil
	}

	t, err := time.ParseDuration(value)
	if err != nil {
		usage := "must be either a boolean or interval"
		return core.NewValueError("auto-update", value, usage, c.isFile)
	}
	c.AutoUpdate = &t
	return nil
}

func (c *Config) ParseCACerts(value string) error {
	data, err := os.ReadFile(value)
	if err != nil {
		if os.IsNotExist(err) {
			return core.FileNotExistsError(value)
		}
		return err
	}

	var ok bool
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		certBytes := block.Bytes
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return invalidCACertError{path: value, err: err}
		}
		ok = true
		c.CACerts = append(c.CACerts, cert)
	}

	if !ok {
		return invalidCACertError{path: value, err: errors.New("no certificates found")}
	}
	return nil
}

func (c *Config) ParseCert(value string) error {
	data, err := os.ReadFile(value)
	if err != nil {
		if os.IsNotExist(err) {
			return core.FileNotExistsError(value)
		}
		return err
	}

	// Verify there's at least a certificate in the file.
	block, _ := pem.Decode(data)
	if block == nil {
		return invalidClientCertError{path: value, err: errors.New("no PEM data found")}
	}
	if block.Type != "CERTIFICATE" {
		return invalidClientCertError{path: value, err: fmt.Errorf("expected CERTIFICATE, got %s", block.Type)}
	}

	c.CertData = data
	c.CertPath = value
	return nil
}

func (c *Config) ParseCopy(value string) error {
	v, err := strconv.ParseBool(value)
	if err != nil {
		return core.NewValueError("copy", value, "must be a boolean", c.isFile)
	}
	c.Copy = &v
	return nil
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

func (c *Config) ParseConnectTimeout(value string) error {
	secs, err := strconv.ParseFloat(value, 64)
	if err != nil || secs < 0 {
		return core.NewValueError("connect-timeout", value, "must be a non-negative number", c.isFile)
	}
	c.ConnectTimeout = core.PointerTo(time.Duration(float64(time.Second) * secs))
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
	key, val, _ := core.CutTrimmed(value, ":")
	c.Headers = append(c.Headers, core.KeyVal[string]{Key: key, Val: val})
	return nil

}

func (c *Config) ParseHTTP(value string) error {
	switch value {
	case "1":
		c.HTTP = core.HTTP1
	case "2":
		c.HTTP = core.HTTP2
	case "3":
		c.HTTP = core.HTTP3
	default:
		const usage = "must be one of [1, 2, 3]"
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

func (c *Config) ParseImageSetting(value string) error {
	switch value {
	case "auto":
		c.Image = core.ImageAuto
	case "native":
		c.Image = core.ImageNative
	case "off":
		c.Image = core.ImageOff
	default:
		const usage = "must be one of [auto, native, off]"
		return core.NewValueError("image", value, usage, c.isFile)
	}
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

func (c *Config) ParseKey(value string) error {
	data, err := os.ReadFile(value)
	if err != nil {
		if os.IsNotExist(err) {
			return core.FileNotExistsError(value)
		}
		return err
	}

	// Verify there's a private key in the file.
	block, _ := pem.Decode(data)
	if block == nil {
		return invalidClientKeyError{path: value, err: errors.New("no PEM data found")}
	}

	// Check for encrypted private keys.
	if strings.Contains(block.Type, "ENCRYPTED") {
		return invalidClientKeyError{path: value, err: errors.New("encrypted private keys are not supported")}
	}

	// Verify it looks like a key block.
	if !strings.Contains(block.Type, "PRIVATE KEY") {
		return invalidClientKeyError{path: value, err: fmt.Errorf("expected PRIVATE KEY, got %s", block.Type)}
	}

	c.KeyData = data
	c.KeyPath = value
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
	key, val, _ := core.CutTrimmed(value, "=")
	c.QueryParams = append(c.QueryParams, core.KeyVal[string]{Key: key, Val: val})
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

func (c *Config) ParseRetry(value string) error {
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		const usage = "must be a non-negative integer"
		return core.NewValueError("retry", value, usage, c.isFile)
	}
	c.Retry = &n
	return nil
}

func (c *Config) ParseRetryDelay(value string) error {
	secs, err := strconv.ParseFloat(value, 64)
	if err != nil || secs < 0 {
		return core.NewValueError("retry-delay", value, "must be a non-negative number", c.isFile)
	}
	c.RetryDelay = core.PointerTo(time.Duration(float64(time.Second) * secs))
	return nil
}

func (c *Config) ParseSession(value string) error {
	if !session.IsValidName(value) {
		const usage = "must contain only alphanumeric characters, hyphens, and underscores"
		return core.NewValueError("session", value, usage, c.isFile)
	}
	c.Session = &value
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

func (c *Config) ParseTiming(value string) error {
	v, err := strconv.ParseBool(value)
	if err != nil {
		return core.NewValueError("timing", value, "must be a boolean", c.isFile)
	}
	c.Timing = &v
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

func (c *Config) ClientCert() (*tls.Certificate, error) {
	if c.CertData == nil {
		return nil, nil
	}

	keyData := c.KeyData
	if keyData == nil {
		// Try using cert file as combined cert+key
		keyData = c.CertData
	}

	cert, err := tls.X509KeyPair(c.CertData, keyData)
	if err == nil {
		return &cert, nil
	}

	// If key was explicitly provided, it's a mismatch error
	if c.KeyData != nil {
		return nil, certKeyMismatchError{certPath: c.CertPath, keyPath: c.KeyPath, err: err}
	}

	// Key wasn't provided and cert file doesn't have embedded key
	return nil, missingClientKeyError{certPath: c.CertPath, err: err}
}

type invalidOptionError string

func (err invalidOptionError) Error() string {
	return fmt.Sprintf("invalid option: '%s'", string(err))
}

func (err invalidOptionError) PrintTo(p *core.Printer) {
	p.WriteString("invalid option: '")
	p.Set(core.Bold)
	p.WriteString(string(err))
	p.Reset()
	p.WriteString("'")
}

type invalidCACertError struct {
	path string
	err  error
}

func (err invalidCACertError) Error() string {
	return fmt.Sprintf("invalid CA certificate '%s': %s", err.path, err.err.Error())
}

func (err invalidCACertError) PrintTo(p *core.Printer) {
	p.WriteString("invalid CA certificate '")
	p.Set(core.Dim)
	p.WriteString(err.path)
	p.Reset()
	p.WriteString("': ")
	p.WriteString(err.err.Error())
}

type invalidClientCertError struct {
	path string
	err  error
}

func (err invalidClientCertError) Error() string {
	return fmt.Sprintf("invalid client certificate '%s': %s", err.path, err.err.Error())
}

func (err invalidClientCertError) PrintTo(p *core.Printer) {
	p.WriteString("invalid client certificate '")
	p.Set(core.Dim)
	p.WriteString(err.path)
	p.Reset()
	p.WriteString("': ")
	p.WriteString(err.err.Error())
}

type invalidClientKeyError struct {
	path string
	err  error
}

func (err invalidClientKeyError) Error() string {
	return fmt.Sprintf("invalid client key '%s': %s", err.path, err.err.Error())
}

func (err invalidClientKeyError) PrintTo(p *core.Printer) {
	p.WriteString("invalid client key '")
	p.Set(core.Dim)
	p.WriteString(err.path)
	p.Reset()
	p.WriteString("': ")
	p.WriteString(err.err.Error())
}

type missingClientKeyError struct {
	certPath string
	err      error
}

func (err missingClientKeyError) Error() string {
	return fmt.Sprintf("client certificate '%s' may require a private key (use --key): %s", err.certPath, err.err.Error())
}

func (err missingClientKeyError) PrintTo(p *core.Printer) {
	p.WriteString("client certificate '")
	p.Set(core.Dim)
	p.WriteString(err.certPath)
	p.Reset()
	p.WriteString("' may require a private key (use '")
	p.Set(core.Bold)
	p.WriteString("--key")
	p.Reset()
	p.WriteString("'): ")
	p.WriteString(err.err.Error())
}

type certKeyMismatchError struct {
	certPath string
	keyPath  string
	err      error
}

func (err certKeyMismatchError) Error() string {
	return fmt.Sprintf("certificate '%s' and key '%s' may not match: %s", err.certPath, err.keyPath, err.err.Error())
}

func (err certKeyMismatchError) PrintTo(p *core.Printer) {
	p.WriteString("certificate '")
	p.Set(core.Dim)
	p.WriteString(err.certPath)
	p.Reset()
	p.WriteString("' and key '")
	p.Set(core.Dim)
	p.WriteString(err.keyPath)
	p.Reset()
	p.WriteString("' may not match: ")
	p.WriteString(err.err.Error())
}
