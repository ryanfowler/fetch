package client

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/ryanfowler/fetch/internal/core"
)

// TLSDialConfig holds the common configuration for building a TLS config
// and dial function.
type TLSDialConfig struct {
	CACerts    []*x509.Certificate
	ClientCert *tls.Certificate
	Insecure   bool
	TLSMax     uint16
	TLSMin     uint16
}

// BuildTLSConfig returns a *tls.Config from the common configuration fields.
func (c *TLSDialConfig) BuildTLSConfig() *tls.Config {
	if c == nil {
		return core.BuildTLSConfig(core.TLSConfigOptions{})
	}
	return core.BuildTLSConfig(core.TLSConfigOptions{
		CACerts:    c.CACerts,
		ClientCert: c.ClientCert,
		Insecure:   c.Insecure,
		TLSMax:     c.TLSMax,
		TLSMin:     c.TLSMin,
	})
}
