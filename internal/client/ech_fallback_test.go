package client

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestDialTLSWithECHPolicyDoesNotFallbackWhenInspectionRejects(t *testing.T) {
	certificate, roots := echTestCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		tlsConn := conn.(*tls.Conn)
		handshakeErr := tlsConn.Handshake()
		_ = tlsConn.Close()
		serverDone <- handshakeErr
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
		// Inspection performs this check after it has received the peer
		// certificate, so the ECH rejection can also be inspected.
		EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, info, err := dialTLSWithECHPolicyInfoAndFallback(ctx, func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", listener.Addr().String())
	}, clientConfig, core.ECHAuto, false, func(tls.ConnectionState) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if info.State == nil || len(info.State.PeerCertificates) == 0 {
		t.Fatalf("rejected ECH state = %#v, want peer certificate", info.State)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

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
