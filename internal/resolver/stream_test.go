package resolver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

func TestStreamClientPipelinesAndCorrelatesOutOfOrderResponses(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		queries := make([][]byte, 2)
		for i := range queries {
			var length [2]byte
			if _, err := io.ReadFull(conn, length[:]); err != nil {
				serverErr <- err
				return
			}
			queries[i] = make([]byte, int(binary.BigEndian.Uint16(length[:])))
			if _, err := io.ReadFull(conn, queries[i]); err != nil {
				serverErr <- err
				return
			}
		}
		// Reply in reverse order. The client must route each response by ID,
		// not by the order in which the queries were written.
		for i := len(queries) - 1; i >= 0; i-- {
			message, err := DecodeMessage(queries[i])
			if err != nil {
				serverErr <- err
				return
			}
			answer := makeRecord(message.Questions[0].Name, message.Questions[0].Type, []byte{192, 0, 2, byte(i + 1)})
			packet := responsePacket(queries[i], message.Header.ID, message.Questions[0], []Record{answer})
			var length [2]byte
			binary.BigEndian.PutUint16(length[:], uint16(len(packet)))
			if _, err := conn.Write(length[:]); err != nil {
				serverErr <- err
				return
			}
			if _, err := conn.Write(packet); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()

	endpoint, err := ParseEndpoint("tcp://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewStreamClient(context.Background(), StreamConfig{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	results := make(chan *Message, 2)
	errs := make(chan error, 2)
	for _, name := range []string{"a.example", "b.example"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			message, err := client.Query(ctx, name, dnsTypeA)
			if err != nil {
				errs <- err
				return
			}
			results <- message
		}(name)
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("received %d responses, want 2", len(results))
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestStreamClientTLSUsesBootstrapAndEndpointSNI(t *testing.T) {
	cert := makeTestCertificate(t, "resolver.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		var length [2]byte
		if _, err := io.ReadFull(tlsConn, length[:]); err != nil {
			serverErr <- err
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(length[:])))
		if _, err := io.ReadFull(tlsConn, query); err != nil {
			serverErr <- err
			return
		}
		message, err := DecodeMessage(query)
		if err != nil {
			serverErr <- err
			return
		}
		packet := responsePacket(query, message.Header.ID, message.Questions[0], nil)
		binary.BigEndian.PutUint16(length[:], uint16(len(packet)))
		if _, err := tlsConn.Write(length[:]); err != nil {
			serverErr <- err
			return
		}
		_, err = tlsConn.Write(packet)
		serverErr <- err
	}()

	endpoint, err := ParseEndpoint("tls://resolver.test:" + endpointPort(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewStreamClient(context.Background(), StreamConfig{
		Endpoint: endpoint,
		Bootstrap: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		CACerts: []*x509.Certificate{cert.Leaf},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.Query(ctx, "example.com", dnsTypeA); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func endpointPort(address string) string {
	_, port, _ := net.SplitHostPort(address)
	return port
}

func makeTestCertificate(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}
