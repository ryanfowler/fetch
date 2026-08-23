package resolver

import "net/http"

// SetRoundTripper replaces the operation-scoped DoH transport after the
// application has assembled its proxy and resolver-aware dial policy. This
// avoids a package cycle while keeping DoH on the same proxy layer as normal
// requests.
func (r *Resolver) SetRoundTripper(transport http.RoundTripper) error {
	return r.setRoundTripper(transport, false)
}

// SetOwnedRoundTripper replaces the operation-scoped DoH transport and makes
// the resolver responsible for closing it. It is intended for a transport
// created specifically for this resolver; shared caller transports should use
// SetRoundTripper instead.
func (r *Resolver) SetOwnedRoundTripper(transport http.RoundTripper) error {
	return r.setRoundTripper(transport, true)
}

func (r *Resolver) setRoundTripper(transport http.RoundTripper, owned bool) error {
	if r == nil || r.endpoint == nil || r.endpoint.Transport != TransportHTTPS {
		return nil
	}
	client, err := NewDOHClient(DOHConfig{
		Endpoint:          r.endpoint,
		RoundTripper:      transport,
		RoundTripperOwned: owned,
		TLSConfig:         r.tlsConfig,
		CACerts:           r.caCerts,
		ClientCert:        r.clientCert,
		Insecure:          r.insecure,
		TLSMin:            r.tlsMin,
		TLSMax:            r.tlsMax,
	})
	if err != nil {
		return err
	}
	old := r.dohClient
	r.dohClient = client
	return old.Close()
}
