package cli

import (
	"github.com/ryanfowler/fetch/internal/config"
	"github.com/ryanfowler/fetch/internal/curl"
)

// provenance is intentionally private: callers should ask App whether an
// option was explicit rather than mutate source state directly.
func (a *App) markOption(name string, source OptionSource) {
	if flag, ok := a.CLI().Options().Lookup(name); ok {
		name = flag.Long
	}
	if a.provenance == nil {
		a.provenance = make(map[string]OptionProvenance)
	}
	p := a.provenance[name]
	if !p.Has(source) {
		p.Sources = append(p.Sources, source)
		a.provenance[name] = p
	}
}

func (a *App) markCLIOption(name string) {
	a.markOption(name, SourceCLI)
}

// OptionProvenance returns the sources that contributed to a canonical option
// in this invocation. A flag's declared default is reported separately by
// the registry and is not stored as mutable App state.
func (a *App) OptionProvenance(name string) OptionProvenance {
	if flag, ok := a.CLI().Options().Lookup(name); ok {
		name = flag.Long
	}
	p := a.provenance[name]
	if len(p.Sources) == 0 {
		if flag, ok := a.CLI().Options().Lookup(name); ok && flag.Default != "" {
			p.Sources = []OptionSource{SourceDefault}
		}
	}
	return p
}

// OptionWasExplicit reports whether the user supplied an option directly or
// through curl import. Config defaults deliberately do not count.
func (a *App) OptionWasExplicit(name string) bool {
	// Preserve the useful pre-registry behavior for callers that construct an
	// App directly (notably package-level diagnostic tests). Parsed invocations
	// always initialize provenance before config merging.
	if a.provenance == nil {
		return true
	}
	p := a.OptionProvenance(name)
	return p.Has(SourceCLI) || p.Has(SourceCurl)
}

// RecordConfigSource records populated config fields after they have been
// merged. Calling this once per scope preserves global versus host provenance
// without making Config itself stateful.
func (a *App) RecordConfigSource(c *config.Config, source OptionSource) {
	if c == nil {
		return
	}
	for _, name := range c.OptionKeys() {
		a.markOption(name, source)
	}
}

// RecordConfigKeys records only the fields that won a particular merge. This
// avoids reporting lower-precedence scalar settings as if they contributed.
func (a *App) RecordConfigKeys(keys []string, source OptionSource) {
	for _, name := range keys {
		a.markOption(name, source)
	}
}

// RecordEnvironment records an environment-derived option for integrations
// that select environment-backed defaults outside the INI parser.
func (a *App) RecordEnvironment(name string) {
	a.markOption(name, SourceEnvironment)
}

func (a *App) markCurlOption(name string) {
	a.markOption(name, SourceCurl)
}

func (a *App) markCurlOptions(r *curl.Result) {
	if r.Method != "" {
		a.markCurlOption("method")
	}
	if len(r.Headers) > 0 || r.UserAgent != "" || r.Referer != "" || r.Cookie != "" {
		a.markCurlOption("header")
	}
	if len(r.DataValues) > 0 || r.UploadFile != "" {
		a.markCurlOption("data")
	}
	if len(r.FormFields) > 0 {
		a.markCurlOption("multipart")
	}
	if r.BasicAuth != "" {
		if r.DigestAuth {
			a.markCurlOption("digest")
		} else {
			a.markCurlOption("basic")
		}
	}
	if r.Bearer != "" {
		a.markCurlOption("bearer")
	}
	if r.AWSSigv4 != "" {
		a.markCurlOption("aws-sigv4")
	}
	if r.Output != "" {
		a.markCurlOption("output")
	}
	if r.RemoteName {
		a.markCurlOption("remote-name")
	}
	if r.RemoteHeaderName {
		a.markCurlOption("remote-header-name")
	}
	if len(r.Ranges) > 0 {
		a.markCurlOption("range")
	}
	if r.UnixSocket != "" {
		a.markCurlOption("unix")
	}
	if r.Insecure {
		a.markCurlOption("insecure")
	}
	if r.TLSVersion != "" {
		a.markCurlOption("min-tls")
	}
	if r.TLSMaxVersion != "" {
		a.markCurlOption("max-tls")
	}
	if r.CACert != "" {
		a.markCurlOption("ca-cert")
	}
	if r.Cert != "" {
		a.markCurlOption("cert")
	}
	if r.Key != "" {
		a.markCurlOption("key")
	}
	if r.TimeoutSet {
		a.markCurlOption("timeout")
	}
	if r.ConnectTimeoutSet {
		a.markCurlOption("connect-timeout")
	}
	if r.Proxy != "" {
		a.markCurlOption("proxy")
	}
	if r.DoHURL != "" {
		a.markCurlOption("dns-server")
	}
	if r.RetrySet {
		a.markCurlOption("retry")
	}
	if r.RetryDelaySet {
		a.markCurlOption("retry-delay")
	}
	if r.FollowRedirects || r.MaxRedirectsSet {
		a.markCurlOption("redirects")
	}
	if r.GetFlag {
		a.markCurlOption("query")
	}
	if r.HTTPVersion != "" {
		a.markCurlOption("http")
	}
	if r.Verbose > 0 {
		a.markCurlOption("verbose")
	}
	if r.Silent {
		a.markCurlOption("silent")
	}
}
