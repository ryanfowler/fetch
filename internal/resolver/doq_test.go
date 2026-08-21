package resolver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestDoQClientPipelinesQueriesOnSeparateStreams(t *testing.T) {
	cert := makeTestCertificate(t, "resolver.test")
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{doqALPN},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErr := make(chan error, 2)
	var serverWG sync.WaitGroup
	serverWG.Add(1)
	go func() {
		defer serverWG.Done()
		conn, err := listener.Accept(context.Background())
		if err != nil {
			if !errors.Is(err, quic.ErrServerClosed) {
				serverErr <- err
			}
			return
		}
		var queryWG sync.WaitGroup
		for i := 0; i < 2; i++ {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				serverErr <- err
				return
			}
			queryWG.Add(1)
			go func() {
				defer queryWG.Done()
				if err := serveDoQQuery(stream); err != nil {
					serverErr <- err
				}
			}()
		}
		queryWG.Wait()
		// Wait for the client to close the operation connection. Closing the
		// QUIC connection immediately after Write would reset queued response
		// data before the client can read it.
		<-conn.Context().Done()
	}()

	endpoint, err := ParseEndpoint("quic://resolver.test:" + endpointPort(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewDoQClient(context.Background(), DoQConfig{
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
	messages, err := client.QueryMany(ctx, []Question{
		{Name: mustParseTestName(t, "example.com"), Type: dnsTypeA, Class: 1},
		{Name: mustParseTestName(t, "example.com"), Type: dnsTypeAAAA, Class: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || len(messages[0].Answers) != 1 || len(messages[1].Answers) != 1 {
		t.Fatalf("messages = %#v, want one answer per query", messages)
	}
	if got := net.IP(messages[0].Answers[0].RData).String(); got != "192.0.2.1" {
		t.Fatalf("A answer = %s, want 192.0.2.1", got)
	}
	if got := net.IP(messages[1].Answers[0].RData).String(); got != "2001:db8::1" {
		t.Fatalf("AAAA answer = %s, want 2001:db8::1", got)
	}

	client.Close()
	listener.Close()
	serverWG.Wait()
	close(serverErr)
	for err := range serverErr {
		t.Fatal(err)
	}
}

func TestResolverLookupIPAddrUsesDoQ(t *testing.T) {
	cert := makeTestCertificate(t, "resolver.test")
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{doqALPN},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErr := make(chan error, 2)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		var queryWG sync.WaitGroup
		for i := 0; i < 2; i++ {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				serverErr <- err
				return
			}
			queryWG.Add(1)
			go func() {
				defer queryWG.Done()
				if err := serveDoQQuery(stream); err != nil {
					serverErr <- err
				}
			}()
		}
		queryWG.Wait()
		<-conn.Context().Done()
	}()

	endpoint, err := ParseEndpoint("doq://resolver.test:" + endpointPort(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	resolver := New(Config{
		Endpoint: endpoint,
		Bootstrap: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		CACerts: []*x509.Certificate{cert.Leaf},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := resolver.LookupIPAddr(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := ipStrings(addrs); strings.Join(got, ",") != "192.0.2.1,2001:db8::1" {
		t.Fatalf("addresses = %v", got)
	}
}

func TestDoQRejectsNonDoQALPN(t *testing.T) {
	cert := makeTestCertificate(t, "resolver.test")
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"not-doq"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept(context.Background())
		if err == nil {
			defer conn.CloseWithError(0, "test complete")
		}
	}()

	endpoint, err := ParseEndpoint("quic://resolver.test:" + endpointPort(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewDoQClient(context.Background(), DoQConfig{
		Endpoint: endpoint,
		Bootstrap: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		CACerts: []*x509.Certificate{cert.Leaf},
	})
	if err == nil || !strings.Contains(err.Error(), "ALPN") {
		t.Fatalf("error = %v, want ALPN error", err)
	}
}

func TestDoQRejectsUntrustedCertificate(t *testing.T) {
	cert := makeTestCertificate(t, "resolver.test")
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{doqALPN},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept(context.Background())
		if err == nil {
			<-conn.Context().Done()
		}
	}()

	endpoint, err := ParseEndpoint("quic://resolver.test:" + endpointPort(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = NewDoQClient(ctx, DoQConfig{
		Endpoint: endpoint,
		Bootstrap: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("error = %v, want certificate verification error", err)
	}
}

func TestDoQRejectsMalformedResponseFrame(t *testing.T) {
	cert := makeTestCertificate(t, "resolver.test")
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{doqALPN},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		var frame [2]byte
		if _, err := io.ReadFull(stream, frame[:]); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(frame[:]))
		query := make([]byte, length)
		if _, err := io.ReadFull(stream, query); err != nil {
			return
		}
		frame = [2]byte{0, 2}
		_, _ = stream.Write(frame[:])
		_, _ = stream.Write([]byte{1})
		_ = stream.Close()
		<-conn.Context().Done()
	}()

	endpoint, err := ParseEndpoint("quic://resolver.test:" + endpointPort(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewDoQClient(context.Background(), DoQConfig{
		Endpoint: endpoint,
		Bootstrap: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		CACerts: []*x509.Certificate{cert.Leaf},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, err = client.Query(ctx, "example.com", dnsTypeA)
	cancel()
	client.Close()
	<-serverDone
	if err == nil {
		t.Fatal("malformed response was accepted")
	}
}

func TestDoQQueryHonorsTimeoutAndAbruptClose(t *testing.T) {
	cert := makeTestCertificate(t, "resolver.test")
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{doqALPN},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		<-conn.Context().Done()
		_ = stream.Close()
	}()

	endpoint, err := ParseEndpoint("quic://resolver.test:" + endpointPort(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewDoQClient(context.Background(), DoQConfig{
		Endpoint: endpoint,
		Bootstrap: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		CACerts: []*x509.Certificate{cert.Leaf},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, err = client.Query(ctx, "example.com", dnsTypeA)
	cancel()
	client.Close()
	<-serverDone
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline", err)
	}
}

func TestDoQReturnsAWhenAAAAStalls(t *testing.T) {
	cert := makeTestCertificate(t, "resolver.test")
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{doqALPN},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		var queryWG sync.WaitGroup
		for i := 0; i < 2; i++ {
			stream, acceptErr := conn.AcceptStream(context.Background())
			if acceptErr != nil {
				return
			}
			queryWG.Add(1)
			go func() {
				defer queryWG.Done()
				defer stream.Close()
				var frame [2]byte
				if _, readErr := io.ReadFull(stream, frame[:]); readErr != nil {
					return
				}
				query := make([]byte, int(binary.BigEndian.Uint16(frame[:])))
				if _, readErr := io.ReadFull(stream, query); readErr != nil {
					return
				}
				message, readErr := DecodeMessage(query)
				if readErr != nil || len(message.Questions) != 1 {
					return
				}
				if message.Questions[0].Type == dnsTypeAAAA {
					<-conn.Context().Done()
					return
				}
				answer := makeRecord(message.Questions[0].Name, dnsTypeA, []byte{192, 0, 2, 1})
				response := responsePacket(query, message.Header.ID, message.Questions[0], []Record{answer})
				binary.BigEndian.PutUint16(frame[:], uint16(len(response)))
				_, _ = stream.Write(frame[:])
				_, _ = stream.Write(response)
			}()
		}
		queryWG.Wait()
	}()

	endpoint, err := ParseEndpoint("quic://resolver.test:" + endpointPort(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	resolver := New(Config{
		Endpoint: endpoint,
		Bootstrap: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		CACerts: []*x509.Certificate{cert.Leaf},
	})
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	addrs, err := resolver.LookupIPAddr(ctx, "example.com")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("stalled family delayed result for %s", elapsed)
	}
	if got := ipStrings(addrs); len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatalf("addresses = %v", got)
	}
	<-serverDone
}

func TestDoQRejectsAbruptRemoteClose(t *testing.T) {
	cert := makeTestCertificate(t, "resolver.test")
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{doqALPN},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		var frame [2]byte
		if _, err := io.ReadFull(stream, frame[:]); err == nil {
			length := int(binary.BigEndian.Uint16(frame[:]))
			query := make([]byte, length)
			_, _ = io.ReadFull(stream, query)
		}
		_ = conn.CloseWithError(0, "abrupt test close")
	}()

	endpoint, err := ParseEndpoint("quic://resolver.test:" + endpointPort(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewDoQClient(context.Background(), DoQConfig{
		Endpoint: endpoint,
		Bootstrap: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		CACerts: []*x509.Certificate{cert.Leaf},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, err = client.Query(ctx, "example.com", dnsTypeA)
	cancel()
	client.Close()
	<-serverDone
	if err == nil {
		t.Fatal("abrupt remote close was accepted")
	}
}

func serveDoQQuery(stream *quic.Stream) error {
	defer stream.Close()
	var frame [2]byte
	if _, err := io.ReadFull(stream, frame[:]); err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint16(frame[:]))
	if length == 0 || length > maxDoQFrame {
		return errors.New("invalid test query length")
	}
	query := make([]byte, length)
	if _, err := io.ReadFull(stream, query); err != nil {
		return err
	}
	message, err := DecodeMessage(query)
	if err != nil {
		return err
	}
	if len(message.Questions) != 1 {
		return errors.New("test query has no question")
	}
	answerData := []byte{192, 0, 2, 1}
	if message.Questions[0].Type == dnsTypeAAAA {
		answerData = net.ParseIP("2001:db8::1").To16()
	}
	answer := makeRecord(message.Questions[0].Name, message.Questions[0].Type, answerData)
	response := responsePacket(query, message.Header.ID, message.Questions[0], []Record{answer})
	binary.BigEndian.PutUint16(frame[:], uint16(len(response)))
	if _, err := stream.Write(frame[:]); err != nil {
		return err
	}
	_, err = stream.Write(response)
	return err
}

func mustParseTestName(t *testing.T, value string) Name {
	t.Helper()
	name, err := ParseName(value)
	if err != nil {
		t.Fatal(err)
	}
	return name
}
