package dnsinspect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"

	"golang.org/x/net/dns/dnsmessage"
)

const dnsTypeCAA dnsmessage.Type = 257

var inspectTypes = []queryType{
	{label: "A", dohType: "A", dnsType: dnsmessage.TypeA},
	{label: "AAAA", dohType: "AAAA", dnsType: dnsmessage.TypeAAAA},
	{label: "CNAME", dohType: "CNAME", dnsType: dnsmessage.TypeCNAME},
	{label: "TXT", dohType: "TXT", dnsType: dnsmessage.TypeTXT},
	{label: "MX", dohType: "MX", dnsType: dnsmessage.TypeMX},
	{label: "NS", dohType: "NS", dnsType: dnsmessage.TypeNS},
	{label: "SOA", dohType: "SOA", dnsType: dnsmessage.TypeSOA},
	{label: "SRV", dohType: "SRV", dnsType: dnsmessage.TypeSRV},
	{label: "CAA", dohType: "CAA", dnsType: dnsTypeCAA},
	{label: "SVCB", dohType: "SVCB", dnsType: dnsmessage.TypeSVCB},
	{label: "HTTPS", dohType: "HTTPS", dnsType: dnsmessage.TypeHTTPS},
}

// Config holds the parameters needed to perform a DNS inspection.
type Config struct {
	// Endpoint is populated by CLI/config validation. DNSServer is retained
	// for direct test fixtures and older internal callers.
	Endpoint   *resolver.Endpoint
	DNSServer  *url.URL
	Proxy      *url.URL
	CACerts    []*x509.Certificate
	TLSConfig  *tls.Config
	ClientCert *tls.Certificate
	Insecure   bool
	TLSMin     uint16
	TLSMax     uint16
	Timeout    time.Duration
	URL        *url.URL
	Silent     bool
	Verbosity  core.Verbosity

	// ResolvConfPath overrides the resolver configuration file consulted when
	// no --dns-server is set. An empty value uses the platform default
	// (/etc/resolv.conf on supported platforms). Tests use it to avoid
	// depending on the host's resolver configuration.
	ResolvConfPath string

	// SystemPolicy supplies the system resolver policy directly. When set it
	// takes precedence over ResolvConfPath. Production callers leave it nil so
	// the policy is loaded from the resolver configuration file; tests use it
	// to select a nameserver with an arbitrary port.
	SystemPolicy *resolver.SystemResolverPolicy
}

type queryType struct {
	label   string
	dohType string
	dnsType dnsmessage.Type
}

type recordSource uint8

const (
	recordSourceDNS recordSource = iota
	recordSourcePlatform
)

// record keeps DNS data in semantic form until it reaches the renderer.
// presentation is only a fallback for DoH JSON and unknown record types whose
// provider did not supply wire-format RDATA.
type record struct {
	owner          string
	typ            dnsmessage.Type
	ttl            uint32
	hasTTL         bool
	source         recordSource
	address        net.IP
	target         string
	target2        string
	preference     uint16
	priority       uint16
	weight         uint16
	port           uint16
	soa            [5]uint32
	txt            [][]byte
	params         []resolver.SVCParam
	rawRData       []byte
	malformedRData bool
	presentation   string
}

type result struct {
	host             string
	queryName        string
	resolver         string
	responders       []string
	transport        string
	security         string
	source           string
	records          map[string][]record
	queries          []queryResult
	failures         []queryFailure
	queryTotal       int
	queryWithData    int
	queryNoData      int
	duration         time.Duration
	tcpFallback      bool
	platformFallback bool
	verbosity        core.Verbosity

	// The following fields are only rendered at -vv. Keeping them in the
	// result, rather than deriving them in the renderer, preserves the
	// resolver policy that was used for this operation.
	configuredNameservers   []string
	resolverAttempts        int
	resolverTimeout         time.Duration
	resolverRotation        string
	resolverConfiguration   string
	resolverRouting         string
	resolverSearchDomains   string
	resolverOSRouting       string
	resolverPlatformRouting string
	resolverBootstrap       string
}

type queryStatus uint8

const (
	queryStatusData queryStatus = iota
	queryStatusNoData
	queryStatusFailed
)

type queryResult struct {
	typ         queryType
	status      queryStatus
	records     []record
	err         error
	responder   string
	transport   resolver.Transport
	attempts    int
	duration    time.Duration
	tcpFallback bool
}

type queryFailure struct {
	label string
	err   error
}

type resolverTargetInfo struct {
	label      string
	udpAddr    string
	useDefault bool
}

var defaultLookupIPAddr = net.DefaultResolver.LookupIPAddr

// systemResolvConfPath is the resolver configuration file used when no
// --dns-server is set. It is a variable so tests can point it at a fixture.
// Windows has no portable resolv.conf to enumerate.
var systemResolvConfPath = func() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/etc/resolv.conf"
}

// loadSystemResolverPolicy reads the system resolver policy. It returns nil
// when the file is unavailable or lists no nameservers.
func loadSystemResolverPolicy(cfg *Config) *resolver.SystemResolverPolicy {
	if cfg.SystemPolicy != nil {
		return cfg.SystemPolicy
	}
	path := cfg.ResolvConfPath
	if path == "" {
		path = systemResolvConfPath()
	}
	if path == "" {
		return nil
	}
	policy, err := resolver.LoadSystemResolverPolicy(path)
	if err != nil {
		return nil
	}
	return &policy
}

func setSystemResolverDetails(out *result, policy resolver.SystemResolverPolicy) {
	out.configuredNameservers = slices.Clone(policy.Nameservers)
	if policy.Attempts > 0 {
		out.resolverAttempts = policy.Attempts
	} else {
		out.resolverAttempts = 2
	}
	if policy.Timeout > 0 {
		out.resolverTimeout = policy.Timeout
	} else {
		out.resolverTimeout = 5 * time.Second
	}
	if policy.Rotate && len(policy.Nameservers) > 1 {
		out.resolverRotation = "enabled"
	} else {
		out.resolverRotation = "disabled"
	}
	out.resolverConfiguration = policy.ResolvConfPath
	caveats := directSystemResolverCaveats(runtime.GOOS)
	out.resolverRouting = caveats.routing
	out.resolverSearchDomains = caveats.searchDomains
	out.resolverOSRouting = caveats.osRouting
	out.resolverPlatformRouting = caveats.platformRouting
}

type systemResolverCaveats struct {
	routing         string
	searchDomains   string
	osRouting       string
	platformRouting string
}

// directSystemResolverCaveats describes the behavior that differs from the
// platform resolver when inspection sends DNS packets to configured
// nameservers. Keep platform-specific caveats separate: macOS has resolver
// scopes and /etc/resolver routing that are not represented by resolv.conf,
// while other supported platforms need the more general direct-query warning.
func directSystemResolverCaveats(goos string) systemResolverCaveats {
	caveats := systemResolverCaveats{
		routing:       "direct nameserver queries",
		searchDomains: "not applied",
	}
	if goos == "darwin" {
		caveats.platformRouting = "scoped/VPN/per-interface and /etc/resolver routing not applied"
	} else {
		caveats.osRouting = "not applied by direct queries"
	}
	return caveats
}

func endpointBootstrapDescription(endpoint *resolver.Endpoint) string {
	if endpoint == nil {
		return ""
	}
	if len(endpoint.BootstrapAddrs) == 0 {
		return "platform resolver for " + endpoint.ConnectHost
	}
	addresses := make([]string, 0, len(endpoint.BootstrapAddrs))
	for _, address := range endpoint.BootstrapAddrs {
		addresses = append(addresses, net.JoinHostPort(address.String(), strconv.Itoa(int(endpoint.Port))))
	}
	return "configured address: " + strings.Join(addresses, ", ")
}

// Inspect resolves the configured URL hostname and renders DNS information to
// the printer. It returns a non-zero exit code on failure.
func Inspect(ctx context.Context, p *core.Printer, cfg *Config) int {
	return InspectWithError(ctx, p, p, cfg)
}

// InspectWithError resolves the configured URL hostname, writes the inspection
// result to output, and writes setup errors to errorOutput. It returns a
// non-zero exit code on failure. Keeping these streams separate lets callers
// pipe a successful inspection without also receiving diagnostics.
func InspectWithError(ctx context.Context, output, errorOutput *core.Printer, cfg *Config) int {
	host := cfg.URL.Hostname()
	if host == "" {
		writeDNSError(errorOutput, errors.New("--inspect-dns requires a hostname"))
		return 1
	}

	// DNS inspection is a diagnostic operation, so it must not leave one
	// stalled resolver query hanging forever. All record-type queries share
	// this single deadline, including resolver endpoint bootstrap.
	inspectionTimeout := cfg.Timeout
	if inspectionTimeout <= 0 {
		inspectionTimeout = core.DefaultDOHTimeout
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, inspectionTimeout)
	defer cancel()

	start := time.Now()
	if isIPLiteral(host) {
		renderIPLiteral(output, host)
		return flushInspectionOutput(output, errorOutput)
	}

	res, err := lookup(ctx, cfg, host, start)
	if err != nil {
		writeDNSError(errorOutput, err)
		return 1
	}
	render(output, res)
	partial := len(res.failures) > 0
	if flushInspectionOutput(output, errorOutput) != 0 {
		return 1
	}
	if partial {
		return 1
	}
	return 0
}

// resolverTransportSecurity reports protection for the connection to the
// resolver. It intentionally says nothing about DNSSEC: fetch does not
// validate DNSSEC chains locally.
func resolverTransportSecurity(cfg *Config, server *url.URL) string {
	if server == nil {
		return "platform resolver (OS-managed security)"
	}

	// Endpoint is the authoritative representation used by production callers.
	// Derive the result from VerifyTLS instead of the display URL so --insecure
	// is reflected without changing endpoint configuration. An HTTPS transport
	// used by an explicit local test endpoint can intentionally have TLS
	// verification disabled and is therefore plaintext, not unverified TLS.
	if cfg.Endpoint != nil {
		if cfg.Endpoint.VerifyTLS {
			if cfg.Insecure {
				return string(resolver.SecurityUnverifiedEncrypt)
			}
			return string(resolver.SecurityVerifiedEncrypted)
		}
		return string(resolver.SecurityPlaintext)
	}

	// DNSServer remains supported for older internal callers. Account for all
	// resolver URL schemes here; treating only https:// as encrypted would
	// misreport legacy DoT and DoQ configurations.
	scheme := strings.ToLower(server.Scheme)
	switch scheme {
	case "tls", "dot", "quic", "doq", "https":
		if cfg.Insecure {
			return string(resolver.SecurityUnverifiedEncrypt)
		}
		return string(resolver.SecurityVerifiedEncrypted)
	default:
		// UDP, TCP, and plain HTTP expose DNS on the wire. --insecure has no
		// certificate verification to disable for these transports.
		return string(resolver.SecurityPlaintext)
	}
}

func resolverURLTransport(server *url.URL) resolver.Transport {
	if server == nil {
		return resolver.TransportUDP
	}
	switch strings.ToLower(server.Scheme) {
	case "tcp":
		return resolver.TransportTCP
	case "tls", "dot":
		return resolver.TransportTLS
	case "quic", "doq":
		return resolver.TransportQUIC
	case "http", "https":
		return resolver.TransportHTTPS
	default:
		return resolver.TransportUDP
	}
}

func resolverTarget(server *url.URL) resolverTargetInfo {
	switch {
	case server == nil:
		return resolverTargetInfo{label: "system resolver", useDefault: true}
	case server.Scheme == "":
		return resolverTargetInfo{label: server.Host, udpAddr: server.Host}
	default:
		return resolverTargetInfo{label: server.String()}
	}
}

func inspectionSource(server *url.URL) string {
	if server == nil {
		return "system resolver configuration"
	}
	return "configured resolver endpoint"
}

func inspectionTransport(cfg *Config, server *url.URL) string {
	if cfg.Endpoint != nil {
		return displayTransport(cfg.Endpoint.Transport)
	}
	if server == nil {
		return "platform resolver"
	}
	switch strings.ToLower(server.Scheme) {
	case "tcp":
		return "TCP"
	case "tls", "dot":
		return "TLS (DoT)"
	case "quic", "doq":
		return "QUIC (DoQ)"
	case "http", "https":
		return "HTTPS (DoH)"
	default:
		return "UDP"
	}
}

func displayTransport(transport resolver.Transport) string {
	switch transport {
	case resolver.TransportTCP:
		return "TCP"
	case resolver.TransportTLS:
		return "TLS (DoT)"
	case resolver.TransportQUIC:
		return "QUIC (DoQ)"
	case resolver.TransportHTTPS:
		return "HTTPS (DoH)"
	case resolver.TransportSystem:
		return "platform resolver"
	default:
		return "UDP"
	}
}

func displaySecurity(security string) string {
	switch security {
	case string(resolver.SecurityPlaintext):
		return "plaintext"
	case string(resolver.SecurityVerifiedEncrypted):
		return "verified TLS"
	case string(resolver.SecurityUnverifiedEncrypt):
		return "encrypted, certificate verification disabled"
	case "platform resolver (OS-managed security)":
		return "OS-managed / unknown to fetch"
	default:
		return security
	}
}

func flushInspectionOutput(output, errorOutput *core.Printer) int {
	if err := output.Flush(); err != nil {
		if core.IsBrokenPipe(err) {
			return 0
		}
		writeDNSError(errorOutput, err)
		return 1
	}
	return 0
}

func writeDNSError(p *core.Printer, err error) {
	core.WriteErrorMsgNoFlush(p, err)
	p.Flush()
}
