package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"testing"
	"time"
)

// forgedNotFound is what a forged plaintext NXDOMAIN for the resolver's own
// name looks like to a bootstrap function.
func forgedNotFound(context.Context, string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{Err: "no such host", Name: "dns.example", IsNotFound: true}
}

// assertBootstrapFailureIsAuthenticated checks that a bootstrap failure of a
// verified resolver is wrapped and cannot be downgraded.
func assertBootstrapFailureIsAuthenticated(t *testing.T, err error) {
	t.Helper()
	var bootstrap *bootstrapError
	if !errors.As(err, &bootstrap) {
		t.Fatalf("error = %v, want a bootstrap error", err)
	}
	classified := classifyDiscoveryError(err, true)
	if DiscoveryFailure(classified) != DiscoveryFailureAuthenticated || MayDowngrade(classified) {
		t.Fatalf("classified = %v (downgrade %t), want a non-downgradable authenticated failure", DiscoveryFailure(classified), MayDowngrade(classified))
	}
}

func TestStreamBootstrapFailureIsAuthenticated(t *testing.T) {
	endpoint, err := ParseEndpoint("tls://dns.example")
	if err != nil {
		t.Fatal(err)
	}
	_, err = dialStreamEndpoint(context.Background(), StreamConfig{Endpoint: endpoint, Bootstrap: forgedNotFound})
	assertBootstrapFailureIsAuthenticated(t, err)
}

func TestDoQBootstrapFailureIsAuthenticated(t *testing.T) {
	endpoint, err := ParseEndpoint("quic://dns.example")
	if err != nil {
		t.Fatal(err)
	}
	_, err = bootstrapDoQEndpoint(context.Background(), DoQConfig{Endpoint: endpoint, Bootstrap: forgedNotFound})
	assertBootstrapFailureIsAuthenticated(t, err)
}

func TestDoHBootstrapFailureIsAuthenticated(t *testing.T) {
	endpoint, err := ParseEndpoint("https://dns.example/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	serverURL, err := url.Parse("https://dns.example/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	dial := dohDialContext(nil, forgedNotFound, endpoint, serverURL, nil)
	_, err = dial(context.Background(), "tcp", "dns.example:443")
	// net/http wraps the dial error in *url.Error.
	assertBootstrapFailureIsAuthenticated(t, &url.Error{Op: "Post", URL: serverURL.String(), Err: err})
}

func TestLookupHTTPSRecordsReturnsTypedNXDOMAIN(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		message, err := DecodeMessage(query)
		if err != nil {
			return
		}
		response := responsePacket(query, message.Header.ID, message.Questions[0], nil)
		// Set RCODE to NXDOMAIN.
		binary.BigEndian.PutUint16(response[2:4], binary.BigEndian.Uint16(response[2:4])&^0x000f|rcodeNXDomain)
		binary.BigEndian.PutUint16(length[:], uint16(len(response)))
		_, _ = conn.Write(append(length[:], response...))
		_, _ = io.Copy(io.Discard, conn)
	}()

	endpoint, err := ParseEndpoint("tcp://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := New(Config{Endpoint: endpoint})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = r.LookupHTTPSRecords(ctx, "example.com")
	var rcode *RCodeError
	if !errors.As(err, &rcode) || rcode.Code != rcodeNXDomain {
		t.Fatalf("LookupHTTPSRecords() error = %v, want a typed NXDOMAIN", err)
	}
	// The same answer from a verified resolver is still a negative answer.
	if got := DiscoveryFailure(classifyDiscoveryError(err, true)); got != DiscoveryFailureNXDOMAIN {
		t.Fatalf("classified = %v, want NXDOMAIN", got)
	}
}
