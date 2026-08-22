package core

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
)

// TLSConfigOptions contains the settings shared by every TLS client in
// fetch. Base is cloned before any option is applied, so callers can safely
// reuse the returned configuration as a template for a connection.
type TLSConfigOptions struct {
	Base       *tls.Config
	CACerts    []*x509.Certificate
	ClientCert *tls.Certificate
	Insecure   bool
	TLSMax     uint16
	TLSMin     uint16
	ServerName string
	NextProtos []string
}

// ValidateTLSVersions validates the TLS bounds accepted by fetch. A zero
// minimum means the secure TLS 1.2 default, and a zero maximum means no cap.
// ValidateECHPolicy validates the ECH mode before any network operation. The
// mode is deliberately independent from the TLS handshake implementation so
// transports cannot silently weaken an explicit policy.
//
// A zero TLS bound means that the caller did not set that bound. In that case
// ECH may raise the effective minimum to TLS 1.3. An explicit TLS 1.2 bound is
// a configuration conflict because it permits a handshake that cannot carry
// ECH.
func ValidateECHPolicy(mode ECHMode, httpVersion HTTPVersion, min, max uint16) error {
	if mode == ECHUnknown || mode == ECHOff {
		return nil
	}
	if err := ValidateTLSVersions(min, max); err != nil {
		return err
	}
	if mode != ECHAuto && mode != ECHOn {
		return fmt.Errorf("unsupported ECH mode %d", mode)
	}
	if mode == ECHOn && httpVersion == HTTP3 {
		return fmt.Errorf("ECH on cannot be used with explicit HTTP/3; use automatic HTTP version selection")
	}
	if min == tls.VersionTLS12 || max == tls.VersionTLS12 {
		return fmt.Errorf("ECH requires TLS 1.3; remove the explicit TLS 1.2 bound")
	}
	return nil
}

func ValidateTLSVersions(min, max uint16) error {
	valid := func(version uint16) bool {
		return version == 0 || version == tls.VersionTLS12 || version == tls.VersionTLS13
	}
	if !valid(min) {
		return fmt.Errorf("unsupported TLS minimum version 0x%x (only TLS 1.2 and 1.3 are supported)", min)
	}
	if !valid(max) {
		return fmt.Errorf("unsupported TLS maximum version 0x%x (only TLS 1.2 and 1.3 are supported)", max)
	}
	effectiveMin := min
	if effectiveMin == 0 {
		effectiveMin = tls.VersionTLS12
	}
	if max != 0 && effectiveMin > max {
		return fmt.Errorf("TLS minimum version is greater than maximum version")
	}
	return nil
}

// TLSVerificationName returns the certificate-verification name for a host.
// It removes URL brackets, IPv6 zone identifiers, and a DNS root dot. Go's TLS
// implementation uses an IP ServerName for SAN verification but omits that IP
// from the SNI extension.
func TLSVerificationName(host string) string {
	name := strings.Trim(host, "[]")
	if zone := strings.LastIndexByte(name, '%'); zone > 0 && net.ParseIP(name[:zone]) != nil {
		name = name[:zone]
	}
	return strings.TrimSuffix(name, ".")
}

// JoinIPHostPort formats an IP address without discarding its IPv6 zone.
func JoinIPHostPort(address net.IPAddr, port string) string {
	host := address.IP.String()
	if address.Zone != "" && address.IP.To4() == nil {
		host += "%" + address.Zone
	}
	return net.JoinHostPort(host, port)
}

// BuildTLSConfig builds an independent TLS configuration using the platform
// verifier by default. Custom roots are added to, rather than substituted for,
// the system roots. The returned configuration can be used as a template and
// must be cloned before a connection-specific mutation.
func BuildTLSConfig(options TLSConfigOptions) *tls.Config {
	config := &tls.Config{}
	if options.Base != nil {
		config = options.Base.Clone()
		if config.RootCAs != nil {
			config.RootCAs = config.RootCAs.Clone()
		}
	}

	if options.TLSMin != 0 {
		config.MinVersion = options.TLSMin
	} else if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS12
	}
	if options.TLSMax != 0 {
		config.MaxVersion = options.TLSMax
	}
	if options.Insecure {
		// InsecureSkipVerify disables certificate-chain and hostname checks. It
		// does not disable the TLS handshake's cryptographic verification.
		config.InsecureSkipVerify = true
	}

	if len(options.CACerts) > 0 {
		pool := config.RootCAs
		if pool == nil {
			pool, _ = x509.SystemCertPool()
		}
		if pool == nil {
			pool = x509.NewCertPool()
		}
		for _, cert := range options.CACerts {
			if cert != nil {
				pool.AddCert(cert)
			}
		}
		config.RootCAs = pool
	}

	if options.ClientCert != nil {
		config.Certificates = []tls.Certificate{cloneTLSCertificate(*options.ClientCert)}
	}
	if options.ServerName != "" {
		config.ServerName = TLSVerificationName(options.ServerName)
	}
	if options.NextProtos != nil {
		config.NextProtos = append([]string(nil), options.NextProtos...)
	}
	return config
}

func cloneTLSCertificate(cert tls.Certificate) tls.Certificate {
	cert.Certificate = cloneByteSlices(cert.Certificate)
	cert.OCSPStaple = append([]byte(nil), cert.OCSPStaple...)
	cert.SignedCertificateTimestamps = cloneByteSlices(cert.SignedCertificateTimestamps)
	return cert
}

func cloneByteSlices(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	cloned := make([][]byte, len(values))
	for i, value := range values {
		cloned[i] = append([]byte(nil), value...)
	}
	return cloned
}
