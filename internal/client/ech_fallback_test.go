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

	unusable := testUnusableECHConfigList(t)
	clientConfig := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     "secret.example",
		RootCAs:                        roots,
		EncryptedClientHelloConfigList: unusable,
		// Inspection performs this check after it has received the peer
		// certificate, so the ECH rejection can also be inspected.
		EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, info, err := dialTLSWithECHPolicyInfoAndFallback(ctx, func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", listener.Addr().String())
	}, clientConfig, core.ECHAuto, func(tls.ConnectionState) bool { return false })
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

func TestDialTLSWithECHPolicyFallsBackAfterRejection(t *testing.T) {
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

	unusable := testUnusableECHConfigList(t)
	clientConfig := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     "secret.example",
		RootCAs:                        roots,
		EncryptedClientHelloConfigList: unusable,
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
		t.Fatal("fallback unexpectedly reported ECH acceptance")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverECHAutoWithoutConfigUsesPlainTLS(t *testing.T) {
	// Auto mode must not offer ECH when no advertised configuration exists.
	// An offer with a made-up public name makes crypto/tls verify the
	// server certificate against that name, and ordinary servers fail.
	// The server certificate therefore covers only the origin name.
	certificate, roots := echTestCertificateFor(t, "secret.example")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		tlsConn := conn.(*tls.Conn)
		handshakeErr := tlsConn.Handshake()
		_ = tlsConn.Close()
		serverErr <- handshakeErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	echConfig, err := discoverECHForConnection(ctx, nil, "secret.example", "443", &tls.Config{RootCAs: roots}, core.ECHAuto, core.HTTP1)
	if err != nil {
		t.Fatal(err)
	}
	if echConfig.Offered() {
		t.Fatal("auto mode offered ECH without an advertised configuration")
	}
	tlsConfig := echConfig.TLSConfig()
	if len(tlsConfig.EncryptedClientHelloConfigList) != 0 {
		t.Fatalf("ECH config list = %x, want empty", tlsConfig.EncryptedClientHelloConfigList)
	}
	if tlsConfig.ServerName != "secret.example" {
		t.Fatalf("ServerName = %q, want secret.example", tlsConfig.ServerName)
	}
	conn, err := dialTLSWithECHPolicy(ctx, func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", listener.Addr().String())
	}, tlsConfig, core.ECHAuto)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}
