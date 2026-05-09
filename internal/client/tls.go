package client

import (
	"crypto/tls"
	"crypto/x509"
)

// TLSDialConfig holds the common configuration for building a TLS config
// and dial function.
type TLSDialConfig struct {
	CACerts    []*x509.Certificate
	ClientCert *tls.Certificate
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
		certPool, err := x509.SystemCertPool()
		if err != nil {
			certPool = x509.NewCertPool()
		}
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
