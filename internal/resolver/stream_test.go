package resolver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
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

// startScriptedStreamServer accepts one connection, reads n queries, and
// writes the frames that reply returns for them, in order.
func startScriptedStreamServer(t *testing.T, n int, reply func(queries [][]byte) [][]byte) (*StreamClient, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		queries := make([][]byte, n)
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
		for _, frame := range reply(queries) {
			var length [2]byte
			binary.BigEndian.PutUint16(length[:], uint16(len(frame)))
			if _, err := conn.Write(append(length[:], frame...)); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
		// Keep the connection open until the client closes it.
		_, _ = io.Copy(io.Discard, conn)
	}()
	endpoint, err := ParseEndpoint("tcp://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewStreamClient(context.Background(), StreamConfig{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client, serverErr
}

// streamReply builds a response to query. A query for the HTTPS type gets
// a record with a repeated SvcParam key, which strict decoding rejects.
func streamReply(t *testing.T, query []byte) []byte {
	t.Helper()
	message, err := DecodeMessage(query)
	if err != nil {
		t.Error(err)
		return nil
	}
	question := message.Questions[0]
	data := []byte{192, 0, 2, 1}
	if question.Type == dnsTypeHTTPS {
		port := svcbParam(svcParamPort, []byte{0x01, 0xbb})
		data = svcbRData(1, nil, port, port)
	}
	answer := makeRecord(question.Name, question.Type, data)
	return responsePacket(query, message.Header.ID, question, []Record{answer})
}

func TestStreamClientMalformedResponseFailsOnlyItsQuery(t *testing.T) {
	for _, badFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("bad first %t", badFirst), func(t *testing.T) {
			client, serverErr := startScriptedStreamServer(t, 2, func(queries [][]byte) [][]byte {
				frames := [][]byte{streamReply(t, queries[0]), streamReply(t, queries[1])}
				// queries[0] is HTTPS. Reply to it first or last.
				if !badFirst {
					frames[0], frames[1] = frames[1], frames[0]
				}
				return frames
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			// Both queries are in flight when the malformed response arrives.
			type result struct {
				message *Message
				err     error
			}
			results := make(chan result, 2)
			for _, typ := range []uint16{dnsTypeHTTPS, dnsTypeA} {
				go func() {
					message, err := client.Query(ctx, "example.com", typ)
					results <- result{message, err}
				}()
				// Keep the write order stable for the server.
				time.Sleep(20 * time.Millisecond)
			}
			var failed, answered int
			for range 2 {
				r := <-results
				switch {
				case r.err != nil:
					if !strings.Contains(r.err.Error(), "invalid DNS stream response") {
						t.Fatalf("error = %v, want a decode error", r.err)
					}
					failed++
				case len(r.message.Answers) == 1:
					answered++
				}
			}
			if failed != 1 || answered != 1 {
				t.Fatalf("failed = %d, answered = %d; want 1 and 1", failed, answered)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStreamClientDropsResponseForUnknownID(t *testing.T) {
	client, serverErr := startScriptedStreamServer(t, 1, func(queries [][]byte) [][]byte {
		stray := streamReply(t, queries[0])
		binary.BigEndian.PutUint16(stray[:2], binary.BigEndian.Uint16(queries[0][:2])+1)
		return [][]byte{stray, streamReply(t, queries[0])}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.Query(ctx, "example.com", dnsTypeA); err != nil {
		t.Fatalf("query after a stray response failed: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestStreamClientShortFrameFailsConnection(t *testing.T) {
	client, _ := startScriptedStreamServer(t, 1, func([][]byte) [][]byte {
		return [][]byte{{0x12, 0x34, 0x81}}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.Query(ctx, "example.com", dnsTypeA); err == nil || !strings.Contains(err.Error(), "shorter than its header") {
		t.Fatalf("Query() error = %v, want a short-frame error", err)
	}
	if _, err := client.Query(ctx, "example.com", dnsTypeA); err == nil {
		t.Fatal("connection stayed open after a frame that is not DNS")
	}
}

func TestStreamClientQuestionMismatchFailsOnlyItsQuery(t *testing.T) {
	client, serverErr := startScriptedStreamServer(t, 2, func(queries [][]byte) [][]byte {
		// Answer the first query with the question of the second.
		wrong := streamReply(t, queries[1])
		binary.BigEndian.PutUint16(wrong[:2], binary.BigEndian.Uint16(queries[0][:2]))
		return [][]byte{wrong, streamReply(t, queries[1])}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	first := make(chan error, 1)
	go func() {
		_, err := client.Query(ctx, "a.example", dnsTypeA)
		first <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := client.Query(ctx, "b.example", dnsTypeA); err != nil {
		t.Fatalf("second query failed: %v", err)
	}
	if err := <-first; err == nil || !strings.Contains(err.Error(), "did not match the query") {
		t.Fatalf("first query error = %v, want a mismatch error", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}
