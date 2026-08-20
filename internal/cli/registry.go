package cli

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// OptionSource identifies where an option value came from. Sources are kept
// on App rather than Config because a Config can be merged from several
// scopes before a request is executed.
type OptionSource uint8

const (
	SourceDefault OptionSource = iota
	SourceGlobalConfig
	SourceHostConfig
	SourceEnvironment
	SourceCurl
	SourceCLI
)

// OptionMode is a user-visible command or request mode understood by the
// option registry.
type OptionMode string

const (
	ModeMetadata      OptionMode = "metadata"
	ModeHTTP          OptionMode = "http"
	ModeGRPC          OptionMode = "grpc"
	ModeGRPCDiscovery OptionMode = "grpc-discovery"
	ModeWebSocket     OptionMode = "websocket"
	ModeDNSInspection OptionMode = "dns-inspection"
	ModeTLSInspection OptionMode = "tls-inspection"
	ModeUpdate        OptionMode = "update"
	ModeSkill         OptionMode = "skill"
)

// OptionProvenance records every source that contributed a value to an
// option. Multiple sources may be present after config merging.
type OptionProvenance struct {
	Sources []OptionSource
}

func (p OptionProvenance) Has(source OptionSource) bool {
	return slices.Contains(p.Sources, source)
}

// OptionRegistry is the single index of the public option surface. Aliases
// resolve to the canonical long name while retaining the original Flag for
// parsing and completion.
type OptionRegistry struct {
	flags    []Flag
	allFlags []Flag
	short    map[string]Flag
	long     map[string]Flag
	byName   map[string]Flag
}

func newOptionRegistry(cli *CLI) *OptionRegistry {
	allFlags := append([]Flag(nil), cli.Flags...)
	for i := range allFlags {
		applyFlagDefinition(&allFlags[i])
	}
	flags := make([]Flag, 0, len(allFlags))
	for _, flag := range allFlags {
		if isFlagVisibleOnOS(flag.OS) {
			flags = append(flags, flag)
		}
	}
	registry := &OptionRegistry{
		short:  make(map[string]Flag),
		long:   make(map[string]Flag),
		byName: make(map[string]Flag),
	}

	for i := range flags {
		flag := &flags[i]
		registry.byName[flag.Long] = *flag
		registry.long[flag.Long] = *flag
		if flag.Short != "" {
			registry.short[flag.Short] = *flag
		}
		for _, alias := range flag.Aliases {
			if len(alias) == 1 {
				registry.short[alias] = *flag
			} else {
				registry.long[alias] = *flag
			}
		}
	}

	// Keep the existing CLI construction readable while making its validation
	// tables registry metadata at runtime. No caller needs to consult both.
	for _, group := range cli.ExclusiveFlags {
		for _, name := range group {
			flag, ok := registry.byName[name]
			if !ok {
				continue
			}
			for _, other := range group {
				if other != name && !slices.Contains(flag.Conflicts, other) {
					flag.Conflicts = append(flag.Conflicts, other)
				}
			}
			registry.setFlag(flag)
		}
	}
	for _, req := range cli.RequiredFlags {
		flag, ok := registry.byName[req.Key]
		if !ok {
			continue
		}
		flag.Requires = append([]string(nil), req.Val...)
		registry.setFlag(flag)
	}
	for scheme, names := range cli.SchemeExclusiveFlags {
		for _, name := range names {
			flag, ok := registry.byName[name]
			if !ok {
				continue
			}
			if !slices.Contains(flag.Schemes, scheme) {
				flag.Schemes = append(flag.Schemes, scheme)
			}
			registry.setFlag(flag)
		}
	}
	for _, name := range cli.FromCurlExclusiveFlags {
		flag, ok := registry.byName[name]
		if !ok {
			continue
		}
		flag.FromCurl = true
		registry.setFlag(flag)
	}

	for i := range flags {
		flags[i] = registry.byName[flags[i].Long]
	}
	registry.flags = flags
	for i := range allFlags {
		if flag, ok := registry.byName[allFlags[i].Long]; ok {
			allFlags[i] = flag
		}
	}
	registry.allFlags = allFlags
	return registry
}

// Flags returns the registry-enriched flags in their declared order.
func (r *OptionRegistry) Flags() []Flag { return append([]Flag(nil), r.flags...) }

func (r *OptionRegistry) ShortFlags() map[string]Flag { return r.short }

func (r *OptionRegistry) LongFlags() map[string]Flag { return r.long }

func (r *OptionRegistry) Lookup(name string) (Flag, bool) {
	flag, ok := r.long[name]
	if !ok {
		flag, ok = r.short[name]
	}
	return flag, ok
}

func (r *OptionRegistry) setFlag(flag Flag) {
	r.byName[flag.Long] = flag
	r.long[flag.Long] = flag
	if flag.Short != "" {
		r.short[flag.Short] = flag
	}
	for _, alias := range flag.Aliases {
		if len(alias) == 1 {
			r.short[alias] = flag
		} else {
			r.long[alias] = flag
		}
	}
}

// Validate checks registry-declared conflicts and requirements using the
// canonical names even when the user supplied an alias.
func (r *OptionRegistry) Validate() error {
	reported := make(map[string]struct{})
	for _, flag := range r.flags {
		if !flag.IsSet() {
			continue
		}
		for _, name := range flag.Conflicts {
			other, ok := r.byName[name]
			if ok && other.IsSet() {
				first, second := flag.Long, other.Long
				if first > second {
					first, second = second, first
				}
				key := first + "\x00" + second
				if _, seen := reported[key]; seen {
					continue
				}
				reported[key] = struct{}{}
				return newExclusiveFlagsError(first, second)
			}
		}
		if len(flag.Requires) == 0 {
			continue
		}
		for _, name := range flag.Requires {
			if required, ok := r.byName[name]; ok && required.IsSet() {
				goto satisfied
			}
		}
		return newRequiredFlagError(flag.Long, flag.Requires)
	satisfied:
	}
	return nil
}

func (r *OptionRegistry) Unsupported(mode OptionMode) (string, bool) {
	for _, flag := range r.flags {
		if flag.IsSet() && (slices.Contains(flag.UnsupportedIn, mode) || (len(flag.Modes) > 0 && !slices.Contains(flag.Modes, mode))) {
			return flag.Long, true
		}
	}
	return "", false
}

func (r *OptionRegistry) ValidateScheme(scheme string) error {
	for _, flag := range r.flags {
		if !flag.IsSet() || !slices.Contains(flag.Schemes, scheme) {
			continue
		}
		return schemeExclusiveError{scheme: scheme, flag: flag.Long}
	}
	return nil
}

// Ignored returns canonical option labels for a mode, filtered to options
// explicitly supplied by the user. Config-only values are intentionally not
// returned.
func (r *OptionRegistry) Ignored(mode OptionMode, explicit func(string) bool) []string {
	seen := make(map[string]struct{})
	var out []string
	flags := r.allFlags
	if len(flags) == 0 {
		flags = r.flags
	}
	for _, flag := range flags {
		if !flag.IsSet() || !slices.Contains(flag.IgnoredIn, mode) || !explicit(flag.Long) {
			continue
		}
		label := flag.IgnoreLabel
		if label == "" {
			label = "--" + flag.Long
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		out = append(out, label)
	}
	order := map[string]int{}
	for i, label := range []string{
		"--data/--json/--xml", "--form", "--multipart", "--grpc", "--grpc-describe", "--grpc-list",
		"--output", "--remote-name", "--remote-header-name", "--copy", "--method", "--header", "--query",
		"--edit", "--session", "--retry", "--range", "--timing", "--proxy", "--discard", "--unix",
		"--inspect-tls", "--bearer", "--basic", "--digest", "--aws-sigv4", "--ca-cert", "--cert", "--key",
		"--tls", "--max-tls", "--insecure", "--format", "--dry-run",
	} {
		order[label] = i
	}
	sort.SliceStable(out, func(i, j int) bool {
		return order[out[i]] < order[out[j]]
	})
	return out
}

func applyFlagDefinition(flag *Flag) {
	if flag.ConfigKey == "" {
		flag.ConfigKey = flag.Long
	}
	if flag.Long == "header" || flag.Long == "query" || flag.Long == "ca-cert" {
		flag.Repeatable = true
	}
	if flag.Long == "form" || flag.Long == "multipart" || flag.Long == "range" || flag.Long == "verbose" {
		flag.Repeatable = true
	}
	if schemes := websocketExcluded[flag.Long]; len(schemes) > 0 {
		flag.Schemes = append([]string(nil), schemes...)
	}
	if fromCurlOptions[flag.Long] {
		flag.FromCurl = true
	}
	// Every option participates in at least one mode. These defaults keep
	// existing flags useful to callers while specialized definitions below
	// narrow the modes where appropriate.
	if len(flag.Modes) == 0 {
		flag.Modes = []OptionMode{ModeHTTP, ModeGRPC, ModeGRPCDiscovery, ModeWebSocket, ModeDNSInspection, ModeTLSInspection, ModeMetadata, ModeUpdate, ModeSkill}
	}
	if flag.Default != "" {
		// The default is represented by the Flag.Default field; this branch is
		// intentionally kept as the registry's single default hook.
	}
	if def, ok := flagDefinitions[flag.Long]; ok {
		if def.ConfigKey != "" {
			flag.ConfigKey = def.ConfigKey
		}
		if def.Repeatable {
			flag.Repeatable = true
		}
		if len(def.Modes) > 0 {
			flag.Modes = append([]OptionMode(nil), def.Modes...)
		}
		if len(def.Conflicts) > 0 {
			flag.Conflicts = append([]string(nil), def.Conflicts...)
		}
		if len(def.Requires) > 0 {
			flag.Requires = append([]string(nil), def.Requires...)
		}
		if len(def.Schemes) > 0 {
			flag.Schemes = append([]string(nil), def.Schemes...)
		}
		if len(def.UnsupportedIn) > 0 {
			flag.UnsupportedIn = append([]OptionMode(nil), def.UnsupportedIn...)
		}
		flag.IgnoredIn = append([]OptionMode(nil), def.IgnoredIn...)
		flag.IgnoreLabel = def.IgnoreLabel
		flag.FromCurl = flag.FromCurl || def.FromCurl
	}
}

var websocketExcluded = map[string][]string{
	"clobber": {"ws", "wss"}, "copy": {"ws", "wss"}, "discard": {"ws", "wss"},
	"edit": {"ws", "wss"}, "form": {"ws", "wss"}, "grpc": {"ws", "wss"},
	"grpc-describe": {"ws", "wss"}, "grpc-list": {"ws", "wss"}, "multipart": {"ws", "wss"},
	"output": {"ws", "wss"}, "remote-header-name": {"ws", "wss"}, "remote-name": {"ws", "wss"},
	"retry": {"ws", "wss"}, "retry-delay": {"ws", "wss"}, "xml": {"ws", "wss"},
}

var fromCurlOptions = map[string]bool{
	"method": true, "header": true, "data": true, "json": true, "xml": true,
	"form": true, "multipart": true, "basic": true, "bearer": true, "digest": true,
	"aws-sigv4": true, "output": true, "remote-name": true, "remote-header-name": true,
	"range": true, "unix": true, "timeout": true, "connect-timeout": true,
	"redirects": true, "proxy": true, "insecure": true, "max-tls": true, "min-tls": true,
	"http": true, "cert": true, "key": true, "ca-cert": true, "dns-server": true,
	"retry": true, "retry-delay": true, "grpc": true, "grpc-describe": true,
	"grpc-list": true, "query": true,
}

var flagDefinitions = map[string]Flag{
	"article":   {Conflicts: []string{"discard", "remote-name", "remote-header-name"}},
	"compress":  {},
	"no-encode": {},
	"ech":       {},
	"har":       {},
	"pager":     {},
	"no-pager":  {},
	"skill":     {Conflicts: []string{"install-skill", "uninstall-skill"}},
	"install-skill": {
		Conflicts: []string{"skill", "uninstall-skill"},
	},
	"uninstall-skill": {
		Conflicts: []string{"skill", "install-skill"},
	},
	"scope":           {Requires: []string{"install-skill", "uninstall-skill"}},
	"force":           {Requires: []string{"install-skill", "uninstall-skill"}},
	"ws-message-mode": {Modes: []OptionMode{ModeWebSocket}},

	"aws-sigv4": {Conflicts: []string{"basic", "bearer", "digest"}, IgnoredIn: []OptionMode{ModeDNSInspection}, FromCurl: true},
	"basic":     {Conflicts: []string{"aws-sigv4", "bearer", "digest"}, IgnoredIn: []OptionMode{ModeDNSInspection}, FromCurl: true},
	"bearer":    {Conflicts: []string{"aws-sigv4", "basic", "digest"}, IgnoredIn: []OptionMode{ModeDNSInspection}, FromCurl: true},
	"digest":    {Conflicts: []string{"aws-sigv4", "basic", "bearer"}, IgnoredIn: []OptionMode{ModeDNSInspection}, FromCurl: true},

	"data":      {Conflicts: []string{"form", "json", "multipart", "xml"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}, IgnoreLabel: "--data/--json/--xml", FromCurl: true, UnsupportedIn: []OptionMode{ModeGRPCDiscovery}},
	"form":      {Conflicts: []string{"data", "json", "multipart", "xml"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}, FromCurl: true, UnsupportedIn: []OptionMode{ModeGRPCDiscovery}},
	"json":      {Conflicts: []string{"data", "form", "multipart", "xml"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}, IgnoreLabel: "--data/--json/--xml", FromCurl: true, UnsupportedIn: []OptionMode{ModeGRPCDiscovery}},
	"multipart": {Conflicts: []string{"data", "form", "json", "xml"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}, FromCurl: true, UnsupportedIn: []OptionMode{ModeGRPCDiscovery}},
	"xml":       {Conflicts: []string{"data", "form", "json", "multipart"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}, IgnoreLabel: "--data/--json/--xml", UnsupportedIn: []OptionMode{ModeGRPCDiscovery}},

	"discard":     {Conflicts: []string{"copy", "output", "remote-name"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}, UnsupportedIn: []OptionMode{ModeGRPCDiscovery}},
	"copy":        {Conflicts: []string{"discard"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}},
	"output":      {Conflicts: []string{"discard", "remote-name"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}, FromCurl: true, UnsupportedIn: []OptionMode{ModeGRPCDiscovery}},
	"remote-name": {Conflicts: []string{"discard", "output"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}, FromCurl: true, UnsupportedIn: []OptionMode{ModeGRPCDiscovery}},

	"proto-file": {Conflicts: []string{"proto-desc"}},
	"proto-desc": {Conflicts: []string{"proto-file"}},
	// Certificate/key pairing is validated after config scopes merge. A CLI
	// key may intentionally pair with a certificate from host or global config.
	"key":                {IgnoredIn: []OptionMode{ModeDNSInspection}, FromCurl: true},
	"proto-import":       {Requires: []string{"proto-file"}},
	"remote-header-name": {Requires: []string{"remote-name"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}, FromCurl: true, UnsupportedIn: []OptionMode{ModeGRPCDiscovery}},
	"ca-cert":            {ConfigKey: "ca-cert", IgnoredIn: []OptionMode{ModeDNSInspection}, FromCurl: true},
	"cert":               {IgnoredIn: []OptionMode{ModeDNSInspection}, FromCurl: true},

	"header":        {IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}},
	"query":         {IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}},
	"grpc":          {Conflicts: []string{"grpc-list", "grpc-describe"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}},
	"grpc-describe": {Conflicts: []string{"grpc", "grpc-list"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}},
	"grpc-list":     {Conflicts: []string{"grpc", "grpc-describe"}, IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}},
	"method":        {IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}, UnsupportedIn: []OptionMode{ModeGRPCDiscovery}},
	"edit":          {IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}, UnsupportedIn: []OptionMode{ModeGRPCDiscovery}},
	"session":       {IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}},
	"retry":         {IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}},
	"range":         {IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}},
	"timing":        {IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}},
	"proxy":         {IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}},
	"unix":          {IgnoredIn: []OptionMode{ModeDNSInspection, ModeTLSInspection}},

	"min-tls":     {ConfigKey: "min-tls", IgnoredIn: []OptionMode{ModeDNSInspection}, IgnoreLabel: "--tls", FromCurl: true},
	"max-tls":     {IgnoredIn: []OptionMode{ModeDNSInspection}, FromCurl: true},
	"insecure":    {IgnoredIn: []OptionMode{ModeDNSInspection}, FromCurl: true},
	"format":      {IgnoredIn: []OptionMode{ModeDNSInspection}},
	"dry-run":     {IgnoredIn: []OptionMode{ModeDNSInspection}},
	"inspect-tls": {IgnoredIn: []OptionMode{ModeDNSInspection}},
	"verbose":     {ConfigKey: "verbosity"},
}

func (r *OptionRegistry) String() string {
	var names []string
	for _, flag := range r.flags {
		names = append(names, flag.Long)
	}
	return fmt.Sprintf("[%s]", strings.Join(names, ", "))
}
