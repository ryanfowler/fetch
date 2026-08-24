package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"
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
	Compress       core.CompressionMode
	Copy           *bool
	// DNSServer is retained for compatibility with older internal consumers.
	// DNSEndpoint is the validated transport-neutral representation used by
	// request construction.
	DNSServer    *url.URL
	DNSEndpoint  *resolver.Endpoint
	ECH          core.ECHMode
	Format       core.Format
	Headers      []core.KeyVal[string]
	HTTP         core.HTTPVersion
	IgnoreStatus *bool
	Image        core.ImageSetting
	Insecure     *bool
	KeyData      []byte
	KeyPath      string
	NoEncode     *bool
	NoPager      *bool
	Pager        core.PagerMode
	Proxy        *url.URL
	QueryParams  []core.KeyVal[string]
	Redirects    *int
	Retry        *int
	RetryDelay   *time.Duration
	RetryUnsafe  *bool
	Session      *string
	Silent       *bool
	Timeout      *time.Duration
	Timing       *bool
	TLSMax       *uint16
	TLSMin       *uint16
	Verbosity    *int
	SortHeaders  *bool
}

// OptionKeys returns canonical CLI option names represented by populated
// config fields. It is used by the CLI provenance layer after each config
// scope is merged.
func (c *Config) OptionKeys() []string {
	var keys []string
	if c.AutoUpdate != nil {
		keys = append(keys, "auto-update")
	}
	if len(c.CACerts) > 0 {
		keys = append(keys, "ca-cert")
	}
	if c.CertPath != "" || c.CertData != nil {
		keys = append(keys, "cert")
	}
	if c.Color != core.ColorUnknown {
		keys = append(keys, "color")
	}
	if c.ConnectTimeout != nil {
		keys = append(keys, "connect-timeout")
	}
	if c.Compress != core.CompressionUnknown {
		keys = append(keys, "compress")
	}
	if c.Copy != nil {
		keys = append(keys, "copy")
	}
	if c.DNSServer != nil || c.DNSEndpoint != nil {
		keys = append(keys, "dns-server")
	}
	if c.ECH != core.ECHUnknown {
		keys = append(keys, "ech")
	}
	if c.Format != core.FormatUnknown {
		keys = append(keys, "format")
	}
	if len(c.Headers) > 0 {
		keys = append(keys, "header")
	}
	if c.HTTP != core.HTTPDefault {
		keys = append(keys, "http")
	}
	if c.IgnoreStatus != nil {
		keys = append(keys, "ignore-status")
	}
	if c.Image != core.ImageUnknown {
		keys = append(keys, "image")
	}
	if c.Insecure != nil {
		keys = append(keys, "insecure")
	}
	if c.KeyPath != "" || c.KeyData != nil {
		keys = append(keys, "key")
	}
	if c.NoEncode != nil {
		keys = append(keys, "no-encode")
	}
	if c.NoPager != nil {
		keys = append(keys, "no-pager")
	}
	if c.Pager != core.PagerUnknown {
		keys = append(keys, "pager")
	}
	if c.Proxy != nil {
		keys = append(keys, "proxy")
	}
	if len(c.QueryParams) > 0 {
		keys = append(keys, "query")
	}
	if c.Redirects != nil {
		keys = append(keys, "redirects")
	}
	if c.Retry != nil {
		keys = append(keys, "retry")
	}
	if c.RetryDelay != nil {
		keys = append(keys, "retry-delay")
	}
	if c.RetryUnsafe != nil {
		keys = append(keys, "retry-unsafe")
	}
	if c.Session != nil {
		keys = append(keys, "session")
	}
	if c.Silent != nil {
		keys = append(keys, "silent")
	}
	if c.Timeout != nil {
		keys = append(keys, "timeout")
	}
	if c.Timing != nil {
		keys = append(keys, "timing")
	}
	if c.TLSMax != nil {
		keys = append(keys, "max-tls")
	}
	if c.TLSMin != nil {
		keys = append(keys, "min-tls")
	}
	if c.Verbosity != nil {
		keys = append(keys, "verbose")
	}
	if c.SortHeaders != nil {
		keys = append(keys, "sort-headers")
	}
	return keys
}

// Merge merges the two Configs together, with "c" taking priority.
func (c *Config) Merge(c2 *Config) []string {
	if c2 == nil {
		return nil
	}
	var applied []string
	add := func(name string) { applied = append(applied, name) }
	if c.AutoUpdate == nil {
		c.AutoUpdate = c2.AutoUpdate
		if c2.AutoUpdate != nil {
			add("auto-update")
		}
	}
	if len(c2.CACerts) > 0 {
		c.CACerts = append(c2.CACerts, c.CACerts...)
		add("ca-cert")
	}
	if c.CertPath == "" && c.CertData == nil && (c2.CertPath != "" || c2.CertData != nil) {
		c.CertData = c2.CertData
		c.CertPath = c2.CertPath
		add("cert")
	}
	// Certificate and key are merged independently. This permits either CLI
	// component to pair with the component supplied by a lower-precedence
	// config scope; validation runs only after all scopes have been merged.
	if c.KeyPath == "" && c.KeyData == nil && (c2.KeyPath != "" || c2.KeyData != nil) {
		c.KeyData = c2.KeyData
		c.KeyPath = c2.KeyPath
		add("key")
	}
	if c.Color == core.ColorUnknown {
		c.Color = c2.Color
		if c2.Color != core.ColorUnknown {
			add("color")
		}
	}
	if c.ConnectTimeout == nil {
		c.ConnectTimeout = c2.ConnectTimeout
		if c2.ConnectTimeout != nil {
			add("connect-timeout")
		}
	}
	if c.Compress == core.CompressionUnknown {
		c.Compress = c2.Compress
		if c2.Compress != core.CompressionUnknown {
			add("compress")
		}
	}
	if c.Copy == nil {
		c.Copy = c2.Copy
		if c2.Copy != nil {
			add("copy")
		}
	}
	if c.DNSServer == nil && c.DNSEndpoint == nil {
		c.DNSServer = c2.DNSServer
		c.DNSEndpoint = c2.DNSEndpoint
		if c2.DNSServer != nil || c2.DNSEndpoint != nil {
			add("dns-server")
		}
	}
	if c.ECH == core.ECHUnknown {
		c.ECH = c2.ECH
		if c2.ECH != core.ECHUnknown {
			add("ech")
		}
	}
	if c.Format == core.FormatUnknown {
		c.Format = c2.Format
		if c2.Format != core.FormatUnknown {
			add("format")
		}
	}
	if len(c2.Headers) > 0 {
		c.Headers = append(c2.Headers, c.Headers...)
		add("header")
	}
	if c.HTTP == core.HTTPDefault {
		c.HTTP = c2.HTTP
		if c2.HTTP != core.HTTPDefault {
			add("http")
		}
	}
	if c.IgnoreStatus == nil {
		c.IgnoreStatus = c2.IgnoreStatus
		if c2.IgnoreStatus != nil {
			add("ignore-status")
		}
	}
	if c.Image == core.ImageUnknown {
		c.Image = c2.Image
		if c2.Image != core.ImageUnknown {
			add("image")
		}
	}
	if c.Insecure == nil {
		c.Insecure = c2.Insecure
		if c2.Insecure != nil {
			add("insecure")
		}
	}
	if c.NoEncode == nil {
		c.NoEncode = c2.NoEncode
		if c2.NoEncode != nil {
			add("no-encode")
		}
	}
	if c.NoPager == nil {
		c.NoPager = c2.NoPager
		if c2.NoPager != nil {
			add("no-pager")
		}
	}
	if c.Pager == core.PagerUnknown {
		c.Pager = c2.Pager
		if c2.Pager != core.PagerUnknown {
			add("pager")
		}
	}
	if c.Proxy == nil {
		c.Proxy = c2.Proxy
		if c2.Proxy != nil {
			add("proxy")
		}
	}
	if len(c2.QueryParams) > 0 {
		c.QueryParams = append(c2.QueryParams, c.QueryParams...)
		add("query")
	}
	if c.Redirects == nil {
		c.Redirects = c2.Redirects
		if c2.Redirects != nil {
			add("redirects")
		}
	}
	if c.Retry == nil {
		c.Retry = c2.Retry
		if c2.Retry != nil {
			add("retry")
		}
	}
	if c.RetryDelay == nil {
		c.RetryDelay = c2.RetryDelay
		if c2.RetryDelay != nil {
			add("retry-delay")
		}
	}
	if c.RetryUnsafe == nil {
		c.RetryUnsafe = c2.RetryUnsafe
		if c2.RetryUnsafe != nil {
			add("retry-unsafe")
		}
	}
	if c.Session == nil {
		c.Session = c2.Session
		if c2.Session != nil {
			add("session")
		}
	}
	if c.Silent == nil {
		c.Silent = c2.Silent
		if c2.Silent != nil {
			add("silent")
		}
	}
	if c.Timeout == nil {
		c.Timeout = c2.Timeout
		if c2.Timeout != nil {
			add("timeout")
		}
	}
	if c.Timing == nil {
		c.Timing = c2.Timing
		if c2.Timing != nil {
			add("timing")
		}
	}
	if c.TLSMax == nil {
		c.TLSMax = c2.TLSMax
		if c2.TLSMax != nil {
			add("max-tls")
		}
	}
	if c.TLSMin == nil {
		c.TLSMin = c2.TLSMin
		if c2.TLSMin != nil {
			add("min-tls")
		}
	}
	if c.Verbosity == nil {
		c.Verbosity = c2.Verbosity
		if c2.Verbosity != nil {
			add("verbose")
		}
	}
	if c.SortHeaders == nil {
		c.SortHeaders = c2.SortHeaders
		if c2.SortHeaders != nil {
			add("sort-headers")
		}
	}
	return applied
}

// Validate checks cross-option constraints that can only be evaluated after
// CLI, global, and host-specific configuration have been merged.
func (c *Config) Validate() error {
	var tlsMin, tlsMax uint16
	if c.TLSMin != nil {
		tlsMin = *c.TLSMin
	}
	if c.TLSMax != nil {
		tlsMax = *c.TLSMax
	}
	if c.TLSMin != nil && c.TLSMax != nil && *c.TLSMin > *c.TLSMax {
		return fmt.Errorf("min-tls must be less than or equal to max-tls")
	}
	if err := core.ValidateTLSVersions(tlsMin, tlsMax); err != nil {
		return err
	}
	if c.HTTP == core.HTTP3 && c.TLSMax != nil && *c.TLSMax < tls.VersionTLS13 {
		return fmt.Errorf("HTTP/3 requires max-tls 1.3 or higher")
	}
	if err := core.ValidateECHPolicy(c.ECH, c.HTTP, tlsMin, tlsMax); err != nil {
		return err
	}
	if c.KeyData != nil && c.CertData == nil {
		return missingClientCertError{keyPath: c.KeyPath}
	}
	if c.CertData != nil {
		_, err := c.ClientCert()
		return err
	}
	return nil
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
	case "compress":
		err = c.ParseCompress(val)
	case "copy":
		err = c.ParseCopy(val)
	case "dns-server":
		err = c.ParseDNSServer(val)
	case "ech":
		err = c.ParseECH(val)
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
	case "pager":
		err = c.ParsePager(val)
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
	case "retry-unsafe":
		err = c.ParseRetryUnsafe(val)
	case "session":
		err = c.ParseSession(val)
	case "silent":
		err = c.ParseSilent(val)
	case "timeout":
		err = c.ParseTimeout(val)
	case "timing":
		err = c.ParseTiming(val)
	case "max-tls":
		err = c.ParseMaxTLS(val)
	case "min-tls":
		err = c.ParseMinTLS(val)
	case "sort-headers":
		err = c.ParseSortHeaders(val)
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
			c.AutoUpdate = new(24 * time.Hour)
		} else {
			c.AutoUpdate = new(time.Duration(-1))
		}
		return nil
	}

	t, err := parseAutoUpdateDuration(value)
	if err != nil {
		usage := "must be either a boolean or interval"
		return core.NewValueError("auto-update", value, usage, c.isFile)
	}
	c.AutoUpdate = &t
	return nil
}

// parseAutoUpdateDuration accepts time.ParseDuration-style values and the
// day unit used by the configuration format. It uses exact rational
// arithmetic so a value near the time.Duration limit is not accepted or
// rejected due to floating-point rounding.
func parseAutoUpdateDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("empty duration")
	}
	if value[0] == '+' {
		value = value[1:]
	}
	if value == "" || value[0] == '-' {
		return 0, errors.New("duration must be non-negative")
	}

	units := []struct {
		name  string
		nanos int64
	}{
		{name: "ns", nanos: int64(time.Nanosecond)},
		{name: "us", nanos: int64(time.Microsecond)},
		{name: "µs", nanos: int64(time.Microsecond)},
		{name: "μs", nanos: int64(time.Microsecond)},
		{name: "ms", nanos: int64(time.Millisecond)},
		{name: "s", nanos: int64(time.Second)},
		{name: "m", nanos: int64(time.Minute)},
		{name: "h", nanos: int64(time.Hour)},
		{name: "d", nanos: int64(24 * time.Hour)},
	}

	total := new(big.Rat)
	for len(value) > 0 {
		start := 0
		digits := 0
		dot := false
		for start < len(value) {
			ch := value[start]
			switch {
			case ch >= '0' && ch <= '9':
				digits++
			case ch == '.' && !dot:
				dot = true
			default:
				goto numberDone
			}
			start++
		}
	numberDone:
		if digits == 0 {
			return 0, errors.New("missing duration value")
		}
		number := value[:start]
		if number[0] == '.' {
			number = "0" + number
		} else if number[len(number)-1] == '.' {
			number += "0"
		}
		rational, ok := new(big.Rat).SetString(number)
		if !ok {
			return 0, errors.New("invalid duration value")
		}

		matched := false
		for _, unit := range units {
			if strings.HasPrefix(value[start:], unit.name) {
				term := new(big.Rat).Mul(rational, new(big.Rat).SetInt64(unit.nanos))
				total.Add(total, term)
				value = value[start+len(unit.name):]
				matched = true
				break
			}
		}
		if !matched {
			return 0, errors.New("missing or invalid duration unit")
		}
	}

	max := new(big.Rat).SetInt64(math.MaxInt64)
	if total.Cmp(max) > 0 {
		return 0, errors.New("duration overflows time.Duration")
	}
	return time.Duration(new(big.Int).Quo(total.Num(), total.Denom()).Int64()), nil
}

func (c *Config) ParseCACerts(value string) error {
	data, err := os.ReadFile(value)
	if err != nil {
		if os.IsNotExist(err) {
			return core.FileNotExistsError(value)
		}
		return invalidCACertError{path: value, err: err}
	}

	var ok bool
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			if len(strings.TrimSpace(string(data))) != 0 {
				return invalidCACertError{path: value, err: errors.New("invalid PEM data")}
			}
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
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
	timeout, err := parseDurationSeconds("connect-timeout", value, "must be a non-negative number", c.isFile)
	if err != nil {
		return err
	}
	c.ConnectTimeout = timeout
	return nil
}

func (c *Config) ParseCompress(value string) error {
	switch value {
	case "auto":
		c.Compress = core.CompressionAuto
	case "br", "brotli":
		c.Compress = core.CompressionBrotli
	case "gzip":
		c.Compress = core.CompressionGzip
	case "zstd":
		c.Compress = core.CompressionZstd
	case "off":
		c.Compress = core.CompressionOff
	default:
		const usage = "must be one of [auto, br, brotli, gzip, zstd, off]"
		return core.NewValueError("compress", value, usage, c.isFile)
	}
	return nil
}

func (c *Config) ParseDNSServer(value string) error {
	endpoint, err := resolver.ParseEndpoint(value)
	// Integration fixtures use a local plaintext HTTP server because they do
	// not need to test TLS. This private test hook is never set by normal CLI
	// operation; production endpoint validation always requires HTTPS for DoH.
	if err != nil && os.Getenv("FETCH_TEST_ALLOW_INSECURE_DNS") == "1" && strings.HasPrefix(strings.ToLower(value), "http://127.0.0.1:") {
		endpoint, err = resolver.ParseEndpointURL(value, true)
	}
	if err != nil {
		return core.NewValueError("dns-server", value, err.Error(), c.isFile)
	}
	c.DNSEndpoint = endpoint
	// Keep the old URL-shaped field populated for integrations that have not
	// migrated yet. Production request construction uses DNSEndpoint.
	c.DNSServer = endpoint.URL()
	return nil
}

func (c *Config) ParseECH(value string) error {
	switch value {
	case "auto":
		c.ECH = core.ECHAuto
	case "on":
		c.ECH = core.ECHOn
	case "off":
		c.ECH = core.ECHOff
	default:
		const usage = "must be one of [auto, on, off]"
		return core.NewValueError("ech", value, usage, c.isFile)
	}
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
	key, val, ok := strings.Cut(value, ":")
	key = strings.TrimSpace(key)
	if !ok || key == "" || !httpguts.ValidHeaderFieldName(key) {
		return core.NewValueError("header", value, "must be in the format NAME:VALUE with a valid non-empty header name", c.isFile)
	}
	if len(val) > 0 && (val[0] == ' ' || val[0] == '\t') {
		val = val[1:]
	}
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
	case "native": // Compatibility spelling retained by the Go baseline.
		c.Image = core.ImageNative
	case "external":
		c.Image = core.ImageExternal
	case "off":
		c.Image = core.ImageOff
	default:
		const usage = "must be one of [auto, external, native, off]"
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

func (c *Config) ParsePager(value string) error {
	switch value {
	case "auto":
		c.Pager = core.PagerAuto
	case "on":
		c.Pager = core.PagerOn
	case "off":
		c.Pager = core.PagerOff
	default:
		const usage = "must be one of [auto, on, off]"
		return core.NewValueError("pager", value, usage, c.isFile)
	}
	return nil
}

func (c *Config) ParseProxy(value string) error {
	proxy, err := url.Parse(value)
	if err != nil {
		return core.NewValueError("proxy", value, core.RedactedErrorText(err), c.isFile)
	}
	c.Proxy = proxy
	return nil
}

func (c *Config) ParseQuery(value string) error {
	key, val, _ := strings.Cut(value, "=")
	c.QueryParams = append(c.QueryParams, core.KeyVal[string]{Key: strings.TrimSpace(key), Val: val})
	return nil
}

func (c *Config) ParseRedirects(value string) error {
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		const usage = "must be a non-negative integer"
		return core.NewValueError("redirects", value, usage, c.isFile)
	}
	c.Redirects = &n
	return nil
}

func (c *Config) ParseRetry(value string) error {
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 || n > core.MaxRetries {
		usage := fmt.Sprintf("must be a non-negative integer no greater than %d", core.MaxRetries)
		return core.NewValueError("retry", value, usage, c.isFile)
	}
	c.Retry = &n
	return nil
}

func (c *Config) ParseRetryDelay(value string) error {
	delay, err := parseDurationSeconds("retry-delay", value, "must be a non-negative number", c.isFile)
	if err != nil {
		return err
	}
	c.RetryDelay = delay
	return nil
}

func (c *Config) ParseRetryUnsafe(value string) error {
	v, err := strconv.ParseBool(value)
	if err != nil {
		return core.NewValueError("retry-unsafe", value, "must be a boolean", c.isFile)
	}
	c.RetryUnsafe = &v
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
	timeout, err := parseDurationSeconds("timeout", value, "must be a non-negative number", c.isFile)
	if err != nil {
		return err
	}
	c.Timeout = timeout
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

func (c *Config) ParseSortHeaders(value string) error {
	v, err := strconv.ParseBool(value)
	if err != nil {
		return core.NewValueError("sort-headers", value, "must be a boolean", c.isFile)
	}
	c.SortHeaders = &v
	return nil
}

func parseTLSVersion(flag, value string, isFile bool) (uint16, error) {
	switch value {
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		const usage = "must be one of [1.2, 1.3]"
		return 0, core.NewValueError(flag, value, usage, isFile)
	}
}

func (c *Config) ParseTLS(value string) error {
	return c.parseMinTLS("tls", value)
}

func (c *Config) ParseMinTLS(value string) error {
	return c.parseMinTLS("min-tls", value)
}

func (c *Config) parseMinTLS(flag, value string) error {
	version, err := parseTLSVersion(flag, value, c.isFile)
	if err != nil {
		return err
	}
	if c.TLSMax != nil && version > *c.TLSMax {
		return core.NewValueError(flag, value, "must be less than or equal to max-tls", c.isFile)
	}
	c.TLSMin = &version
	return nil
}

func (c *Config) ParseMaxTLS(value string) error {
	version, err := parseTLSVersion("max-tls", value, c.isFile)
	if err != nil {
		return err
	}
	if c.TLSMin != nil && version < *c.TLSMin {
		return core.NewValueError("max-tls", value, "must be greater than or equal to min-tls", c.isFile)
	}
	c.TLSMax = &version
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

func parseDurationSeconds(flag, value, usage string, isFile bool) (*time.Duration, error) {
	duration, err := core.ParseSeconds(value)
	if err != nil {
		return nil, core.NewValueError(flag, value, usage, isFile)
	}
	return &duration, nil
}

func (c *Config) ClientCert() (*tls.Certificate, error) {
	if c.CertData == nil {
		if c.KeyData != nil {
			return nil, missingClientCertError{keyPath: c.KeyPath}
		}
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

type missingClientCertError struct {
	keyPath string
}

func (err missingClientCertError) Error() string {
	return "flag '--key' requires '--cert'"
}

func (err missingClientCertError) PrintTo(p *core.Printer) {
	p.WriteString("flag '")
	p.Set(core.Bold)
	p.WriteString("--key")
	p.Reset()
	p.WriteString("' requires '")
	p.Set(core.Bold)
	p.WriteString("--cert")
	p.Reset()
	p.WriteString("'")
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
