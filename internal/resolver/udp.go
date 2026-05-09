package resolver

import (
	"context"
	"net"
)

func udpResolver(serverAddr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, serverAddr)
		},
	}
}
