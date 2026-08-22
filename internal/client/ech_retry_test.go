package client

import (
	"context"
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestDialTLSWithECHPolicyRetriesServerConfig(t *testing.T) {
	certificate, roots := echTestCertificate(t)
	serverKey, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverConfigBytes := testECHConfig(11, serverKey.PublicKey().Bytes(), "public.example")
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
			Config:      serverConfigBytes,
			PrivateKey:  serverKey.Bytes(),
			SendAsRetry: true,
		}},
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
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
			lastErr = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
		serverErr <- lastErr
	}()

	clientKey, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     "secret.example",
		RootCAs:                        roots,
		EncryptedClientHelloConfigList: testECHConfigList(testECHConfig(12, clientKey.PublicKey().Bytes(), "public.example")),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialTLSWithECHPolicy(ctx, func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", listener.Addr().String())
	}, clientConfig, core.ECHOn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !conn.(*tls.Conn).ConnectionState().ECHAccepted {
		t.Fatal("ECH retry succeeded without acceptance")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}
