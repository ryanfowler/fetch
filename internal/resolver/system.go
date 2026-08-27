package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	defaultSystemResolverAttempts = 2
	defaultSystemResolverTimeout  = 5 * time.Second
)

// SystemResolverPolicy describes the portable subset of resolv.conf policy
// that can be applied to raw DNS queries. The ordinary resolver still uses the
// platform API for A/AAAA lookups, which preserves NSS and OS-specific
// routing.
type SystemResolverPolicy struct {
	Nameservers []string
	Attempts    int
	Timeout     time.Duration
	Rotate      bool

	// UseSystemdResolved prefers resolvectl on Linux. Tests can disable it or
	// provide a resolv.conf path without depending on the host's resolver.
	UseSystemdResolved bool
	ResolvConfPath     string
}

// ParseResolvConf parses nameservers and the supported resolver options from a
// resolv.conf-like document. Invalid nameserver entries are skipped so one
// malformed line does not discard usable resolver policy.
func ParseResolvConf(data string) SystemResolverPolicy {
	policy := SystemResolverPolicy{
		Attempts: defaultSystemResolverAttempts,
		Timeout:  defaultSystemResolverTimeout,
	}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "nameserver":
			if addr := parseSystemNameserver(fields[1]); addr != "" && !containsSystemNameserver(policy.Nameservers, addr) && len(policy.Nameservers) < maxSystemNameservers {
				policy.Nameservers = append(policy.Nameservers, addr)
			}
		case "options":
			for _, option := range fields[1:] {
				key, value, hasValue := strings.Cut(strings.ToLower(option), ":")
				switch key {
				case "rotate":
					if !hasValue {
						policy.Rotate = true
					}
				case "attempts":
					if n, err := strconv.Atoi(value); hasValue && err == nil && n > 0 && n <= 10 {
						policy.Attempts = n
					}
				case "timeout":
					if n, err := strconv.Atoi(value); hasValue && err == nil && n > 0 && n <= 300 {
						policy.Timeout = time.Duration(n) * time.Second
					}
				}
			}
		}
	}
	return policy
}

// LoadSystemResolverPolicy reads a resolver configuration file using the
// supported system policy subset. It does not fail because one nameserver
// line is malformed; callers receive an error only when the file itself is
// unavailable.
func LoadSystemResolverPolicy(path string) (SystemResolverPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SystemResolverPolicy{}, err
	}
	policy := ParseResolvConf(string(data))
	policy.ResolvConfPath = path
	policy.UseSystemdResolved = runtime.GOOS == "linux" && path == "/etc/resolv.conf"
	return policy, nil
}

const maxSystemNameservers = 16

func containsSystemNameserver(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

func parseSystemNameserver(value string) string {
	if ip := net.ParseIP(value); ip != nil {
		return net.JoinHostPort(ip.String(), "53")
	}
	return ""
}

var systemResolverRotation atomic.Uint32

// QuerySystemHTTPS queries the configured system resolver policy for an
// HTTPS or SVCB record. It is kept separate from Resolver so callers can use
// it for automatic HTTP/3/ECH discovery without changing ordinary platform
// A/AAAA resolution.
func QuerySystemHTTPS(ctx context.Context, policy SystemResolverPolicy, host string, typ uint16) ([]Record, error) {
	if typ != dnsTypeHTTPS && typ != dnsTypeSVCB {
		return nil, fmt.Errorf("system service lookup does not support DNS type %d", typ)
	}
	records, _, err := QuerySystemType(ctx, policy, host, typ)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(records))
	for _, record := range records {
		if record.Type == typ {
			out = append(out, record)
		}
	}
	if len(out) == 0 {
		return nil, errDNSNoData
	}
	return out, nil
}

// RotateSystemResolverPolicy applies resolv.conf rotation once and disables
// per-query rotation. This is useful for one diagnostic operation whose
// concurrent queries should use the same ordered nameserver set.
func RotateSystemResolverPolicy(policy SystemResolverPolicy) SystemResolverPolicy {
	if !policy.Rotate || len(policy.Nameservers) < 2 {
		policy.Rotate = false
		return policy
	}
	start := int(systemResolverRotation.Add(1)-1) % len(policy.Nameservers)
	policy.Nameservers = append(slices.Clone(policy.Nameservers[start:]), policy.Nameservers[:start]...)
	policy.Rotate = false
	return policy
}

// QuerySystemType resolves host for an arbitrary DNS record type using the
// configured system nameservers, honoring the resolv.conf attempts, rotate,
// and timeout policy. The boolean reports whether any nameserver required a
// TCP fallback. systemd-resolved is consulted only for HTTPS/SVCB because
// resolvectl does not expose other record types.
func QuerySystemType(ctx context.Context, policy SystemResolverPolicy, host string, typ uint16) ([]Record, bool, error) {
	if policy.UseSystemdResolved && runtime.GOOS == "linux" && (typ == dnsTypeHTTPS || typ == dnsTypeSVCB) {
		if records, err := querySystemdResolved(ctx, host, typ); err == nil && len(records) > 0 {
			return records, false, nil
		}
	}
	if len(policy.Nameservers) == 0 {
		return nil, false, ErrHTTPSRecordsUnavailable
	}
	attempts := policy.Attempts
	if attempts <= 0 {
		attempts = defaultSystemResolverAttempts
	}
	timeout := policy.Timeout
	if timeout <= 0 {
		timeout = defaultSystemResolverTimeout
	}
	start := 0
	if policy.Rotate {
		start = int(systemResolverRotation.Add(1)-1) % len(policy.Nameservers)
	}
	var lastErr error
	var totalFallback bool
	for offset := range len(policy.Nameservers) {
		index := (start + offset) % len(policy.Nameservers)
		queryCtx, cancel := context.WithTimeout(ctx, timeout)
		message, fallback, err := lookupUDPMessage(queryCtx, policy.Nameservers[index], host, typ, attempts)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		name, err := ParseName(host)
		if err != nil {
			return nil, fallback, err
		}
		if message.Header.RCode != 0 {
			return nil, fallback, fmt.Errorf("DNS response: %s", RCodeName(message.Header.RCode))
		}
		authorized, err := AuthorizeAnswers(message, Question{Name: name, Type: typ, Class: 1})
		if err != nil {
			return nil, fallback, err
		}
		out := make([]Record, 0, len(authorized))
		hasRequestedType := false
		for _, record := range authorized {
			out = append(out, record)
			hasRequestedType = hasRequestedType || record.Type == typ
		}
		if !hasRequestedType {
			return nil, fallback, errDNSNoData
		}
		if fallback {
			totalFallback = true
		}
		return out, totalFallback, nil
	}
	if err := contextError(ctx); err != nil {
		return nil, totalFallback, err
	}
	if lastErr == nil {
		lastErr = errors.New("system resolver query failed")
	}
	return nil, totalFallback, lastErr
}

func querySystemdResolved(ctx context.Context, host string, typ uint16) ([]Record, error) {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return nil, err
	}
	typeName := "HTTPS"
	if typ == dnsTypeSVCB {
		typeName = "SVCB"
	}
	cmd := exec.CommandContext(ctx, "resolvectl", "--no-pager", "--legend=no", "query", "--type="+typeName, host)
	var output boundedSystemOutput
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	data := output.Bytes()
	owner, err := ParseName(host)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		marker := " IN " + typeName + " "
		index := strings.Index(strings.ToUpper(line), marker)
		if index < 0 {
			continue
		}
		value := strings.TrimSpace(line[index+len(marker):])
		parsed, raw, err := parseJSONSVCBPresentation(value)
		if err != nil {
			return nil, fmt.Errorf("invalid resolvectl %s record: %w", typeName, err)
		}
		records = append(records, Record{Owner: owner, Type: typ, Class: 1, RData: raw, Priority: parsed.Priority, Target: &parsed.Target, Params: cloneSVCBParams(parsed.Params)})
	}
	if len(records) == 0 {
		return nil, errDNSNoData
	}
	if err := ValidateSVCBRRSet(records); err != nil {
		return nil, err
	}
	return records, nil
}

type boundedSystemOutput struct {
	data []byte
}

func (b *boundedSystemOutput) Write(p []byte) (int, error) {
	const maxOutput = 64 << 10
	if len(p) > maxOutput-len(b.data) {
		return 0, fmt.Errorf("resolvectl output exceeds %d bytes", maxOutput)
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *boundedSystemOutput) Bytes() []byte { return b.data }
