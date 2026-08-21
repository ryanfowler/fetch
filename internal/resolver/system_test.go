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
