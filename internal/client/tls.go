package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
)

// TLSDialConfig holds the common configuration for building a TLS config
// and dial function.
type TLSDialConfig struct {
	CACerts    []*x509.Certificate
	ClientCert *tls.Certificate
	DNSServer  *url.URL
	Insecure   bool
	TLS        uint16
}

// BuildTLSConfig returns a *tls.Config from the common configuration fields.
func (c *TLSDialConfig) BuildTLSConfig() *tls.Config {
	tlsConfig := &tls.Config{}

	tlsVersion := c.TLS
	if tlsVersion == 0 {
		tlsVersion = tls.VersionTLS12
	}
	tlsConfig.MinVersion = tlsVersion

	if c.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}
	if len(c.CACerts) > 0 {
		certPool := x509.NewCertPool()
		for _, cert := range c.CACerts {
			certPool.AddCert(cert)
		}
		tlsConfig.RootCAs = certPool
	}
	if c.ClientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*c.ClientCert}
	}

	return tlsConfig
}

// BuildDialer returns a net.Dialer configured with the DNS server, if any.
func (c *TLSDialConfig) BuildDialer() *net.Dialer {
	dialer := &net.Dialer{}
	if c.DNSServer != nil {
		if c.DNSServer.Scheme == "" {
			dialer.Resolver = udpResolver(c.DNSServer.Host)
		}
	}
	return dialer
}

// BuildDialContext returns a dial context function that uses the configured DNS
// server, supporting both UDP and DoH (DNS over HTTPS).
func (c *TLSDialConfig) BuildDialContext() func(ctx context.Context, network, address string) (net.Conn, error) {
	if c.DNSServer == nil {
		return nil
	}
	if c.DNSServer.Scheme == "" {
		return dialContextUDP(c.DNSServer.Host)
	}
	return dialContextDOH(c.DNSServer)
}
