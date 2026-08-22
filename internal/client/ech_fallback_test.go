package client

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestDialTLSWithECHPolicyGreaseFallsBackAfterRejection(t *testing.T) {
	certificate, roots := echTestCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		var lastErr error
		for attempt := 0; attempt < 2; attempt++ {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverErr <- acceptErr
				return
			}
			tlsConn := conn.(*tls.Conn)
			lastErr = tlsConn.Handshake()
			_ = tlsConn.Close()
			if lastErr == nil && attempt == 1 {
				serverErr <- nil
				return
			}
		}
		serverErr <- lastErr
	}()

	grease, err := GenerateGREASEECHConfigList()
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     "secret.example",
		RootCAs:                        roots,
		EncryptedClientHelloConfigList: grease,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialTLSWithECHPolicy(ctx, func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", listener.Addr().String())
	}, clientConfig, core.ECHAuto)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.(*tls.Conn).ConnectionState().ECHAccepted {
		t.Fatal("GREASE fallback unexpectedly reported ECH acceptance")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}
