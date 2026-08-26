package client

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/resolver"
)

func TestDialResolverWithECHUsesResolveOriginPort(t *testing.T) {
	res := resolver.New(resolver.Config{Resolve: []resolver.ResolveEntry{{
		Host: "origin.test", Port: "443", IP: net.ParseIP("192.0.2.10"),
	}}})
	var dialed string
	dialer := NewResolverDialer(res, time.Second)
	dialer.BaseDial = func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		return nil, errors.New("stop before TLS")
	}

	_, err := dialResolverWithECHInfo(context.Background(), dialer, DialRequest{
		Network: "tcp", Host: "edge.test", Port: "8443", OriginHost: "origin.test", OriginPort: "0443",
		Resolver: res, Candidates: []net.IPAddr{{IP: net.ParseIP("192.0.2.11")}},
	}, &tls.Config{}, core.ECHOff, false)
	if err == nil {
		t.Fatal("dialResolverWithECHInfo succeeded, want test dial failure")
	}
	if dialed != "192.0.2.10:443" {
		t.Fatalf("dial address = %q, want 192.0.2.10:443", dialed)
	}
}

func TestDialTLSWithECHPolicyAcceptsRealECH(t *testing.T) {
	certificate, roots := echTestCertificate(t)
	echPrivate, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	echConfig := testECHConfig(7, echPrivate.PublicKey().Bytes(), "public.example")
	privateKeyBytes := echPrivate.Bytes()
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
			Config:     echConfig,
			PrivateKey: privateKeyBytes,
		}},
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
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
		defer conn.Close()
		serverErr <- conn.(*tls.Conn).Handshake()
	}()

	clientConfig := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     "secret.example",
		RootCAs:                        roots,
		EncryptedClientHelloConfigList: testECHConfigList(echConfig),
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
		t.Fatal("client handshake succeeded without ECH acceptance")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func echTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fetch ECH test"},
		DNSNames:     []string{"public.example", "secret.example"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, func() *x509.CertPool {
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		return pool
	}()
}

func testECHConfig(id byte, publicKey []byte, publicName string) []byte {
	contents := []byte{id}
	contents = appendUint16(contents, greaseECHKEM)
	contents = appendUint16(contents, uint16(len(publicKey)))
	contents = append(contents, publicKey...)
	contents = appendUint16(contents, 4)
	contents = appendUint16(contents, greaseECHKDF)
	contents = appendUint16(contents, greaseECHAES128GCM)
	contents = append(contents, 32, byte(len(publicName)))
	contents = append(contents, []byte(publicName)...)
	contents = appendUint16(contents, 0)
	config := appendUint16(nil, greaseECHVersion)
	config = appendUint16(config, uint16(len(contents)))
	config = append(config, contents...)
	return config
}

func testECHConfigList(config []byte) []byte {
	list := appendUint16(nil, uint16(len(config)))
	return append(list, config...)
}
