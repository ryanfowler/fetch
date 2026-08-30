package resolver

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLoadSystemResolverPolicy(t *testing.T) {
	path := t.TempDir() + "/resolv.conf"
	if err := os.WriteFile(path, []byte("nameserver 192.0.2.53\noptions attempts:3 timeout:1"), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := LoadSystemResolverPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if policy.ResolvConfPath != path || len(policy.Nameservers) != 1 || policy.Attempts != 3 || policy.Timeout != time.Second {
		t.Fatalf("policy = %+v", policy)
	}
}

func TestQuerySystemTypeRetriesAcrossNameservers(t *testing.T) {
	// A silent UDP socket as the first nameserver forces a retry to the
	// working second nameserver.
	blackHole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackHole.Close()

	server := newUDPTestServer(t)
	defer server.close()

	done := make(chan error, 1)
	go func() {
		query, client, err := server.readQuery()
		if err != nil {
			done <- err
			return
		}
		message, err := DecodeMessage(query)
		if err != nil {
			done <- err
			return
		}
		question := message.Questions[0]
		answer := makeRecord(question.Name, dnsTypeA, net.IPv4(192, 0, 2, 55).To4())
		_, err = server.udp.WriteToUDP(responsePacket(query, message.Header.ID, question, []Record{answer}), client)
		done <- err
	}()

	policy := SystemResolverPolicy{
		Nameservers: []string{blackHole.LocalAddr().String(), server.addr()},
		Attempts:    1,
		Timeout:     100 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	records, _, err := QuerySystemType(ctx, policy, "example.com", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Type != dnsTypeA {
		t.Fatalf("records = %#v, want one A record", records)
	}
	if got, want := net.IP(records[0].RData).String(), "192.0.2.55"; got != want {
		t.Fatalf("A address = %s, want %s", got, want)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestQuerySystemTypePropagatesFailedTCPFallback(t *testing.T) {
	server, tcp := newUDPAndTCPTestServer(t)
	defer server.close()
	defer tcp.Close()

	done := make(chan error, 1)
	go func() {
		query, client, err := server.readQuery()
		if err != nil {
			done <- err
			return
		}
		message, err := DecodeMessage(query)
		if err != nil {
			done <- err
			return
		}
		truncated := responsePacket(query, message.Header.ID, message.Questions[0], nil)
		_, err = server.udp.WriteToUDP(withTruncatedFlag(truncated), client)
		if err != nil {
			done <- err
			return
		}
		connection, err := tcp.AcceptTCP()
		if err != nil {
			done <- err
			return
		}
		_ = connection.Close()
		done <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, fallback, err := QuerySystemType(ctx, SystemResolverPolicy{
		Nameservers: []string{server.addr()},
		Attempts:    1,
		Timeout:     time.Second,
	}, "example.com", dnsTypeA)
	if err == nil || !strings.Contains(err.Error(), "DNS TCP fallback") {
		t.Fatalf("error = %v, want failed TCP fallback", err)
	}
	if !fallback {
		t.Fatal("fallback = false, want attempted TCP fallback")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func withTruncatedFlag(packet []byte) []byte {
	packet = append([]byte(nil), packet...)
	flags := uint16(packet[2])<<8 | uint16(packet[3])
	flags |= 0x0200
	packet[2] = byte(flags >> 8)
	packet[3] = byte(flags)
	return packet
}

func TestParseResolvConfSkipsMalformedNameserversAndReadsPolicy(t *testing.T) {
	policy := ParseResolvConf(strings.TrimSpace(`
# comments and malformed entries are ignored
nameserver not-an-ip
nameserver 2001:db8::1
nameserver 192.0.2.1
options rotate attempts:4 timeout:2
options attempts:0 timeout:nope
`))
	if got, want := policy.Nameservers, []string{"[2001:db8::1]:53", "192.0.2.1:53"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("nameservers = %v, want %v", got, want)
	}
	if !policy.Rotate || policy.Attempts != 4 || policy.Timeout != 2*time.Second {
		t.Fatalf("policy = %+v, want rotate, attempts 4, timeout 2s", policy)
	}
}

func TestResolverDialContextUsesConfiguredLookupAndHappyEyeballs(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	resolver := New(Config{
		SystemLookupIPAddr: func(_ context.Context, host string) ([]net.IPAddr, error) {
			if host != "service.test" {
				return nil, net.UnknownNetworkError("unexpected system lookup")
			}
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	})
	conn, err := resolver.DialContext(context.Background(), "tcp", "service.test:"+strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case peer := <-accepted:
		peer.Close()
	case <-time.After(time.Second):
		t.Fatal("dial did not reach the configured address")
	}
}
