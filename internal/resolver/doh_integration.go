package resolver

import "net/http"

// SetRoundTripper replaces the operation-scoped DoH transport after the
// application has assembled its proxy and resolver-aware dial policy. This
// avoids a package cycle while keeping DoH on the same proxy layer as normal
// requests.
func (r *Resolver) SetRoundTripper(transport http.RoundTripper) error {
	if r == nil || r.endpoint == nil || r.endpoint.Transport != TransportHTTPS {
		return nil
	}
	client, err := NewDOHClient(DOHConfig{
		Endpoint:     r.endpoint,
		RoundTripper: transport,
		TLSConfig:    r.tlsConfig,
		CACerts:      r.caCerts,
		ClientCert:   r.clientCert,
		Insecure:     r.insecure,
		TLSMin:       r.tlsMin,
		TLSMax:       r.tlsMax,
	})
	if err != nil {
		return err
	}
	r.dohClient = client
	return nil
}
