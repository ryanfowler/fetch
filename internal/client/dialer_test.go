package client

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/resolver"
)

func TestResolverDialerResolvesAndReportsWinningAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	res := resolver.New(resolver.Config{
		SystemLookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	})
	dialer := NewResolverDialer(res, time.Second)
	result, err := dialer.Dial(context.Background(), DialRequest{
		Network: "tcp",
		Host:    "service.test",
		Port:    strconv.Itoa(listener.Addr().(*net.TCPAddr).Port),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Conn.Close()
	if got, want := result.RemoteIP.String(), "127.0.0.1"; got != want {
		t.Fatalf("remote IP = %s, want %s", got, want)
	}
	if result.Resolver != "system" {
		t.Fatalf("resolver provenance = %q, want system", result.Resolver)
	}
	if result.Timing.ConnectDuration <= 0 {
		t.Fatalf("connect duration = %s, want positive duration", result.Timing.ConnectDuration)
	}
	select {
	case conn := <-accepted:
		conn.Close()
	case <-time.After(time.Second):
		t.Fatal("listener did not receive the connection")
	}
}

func TestResolverDialerUsesStaticResolveEntry(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	lookupCalled := false
	res := resolver.New(resolver.Config{
		Resolve: []resolver.ResolveEntry{{
			Host: "service.test", Port: strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), IP: net.ParseIP("127.0.0.1"),
		}},
		SystemLookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
			lookupCalled = true
			return nil, errors.New("unexpected lookup")
		},
	})
	dialer := NewResolverDialer(res, time.Second)
	result, err := dialer.Dial(context.Background(), DialRequest{
		Network: "tcp",
		Host:    "service.test",
		Port:    strconv.Itoa(listener.Addr().(*net.TCPAddr).Port),
	})
	if err != nil {
		t.Fatal(err)
	}
	result.Conn.Close()
	if lookupCalled {
		t.Fatal("static resolve entry performed a DNS lookup")
	}
	if got := result.RemoteIP.String(); got != "127.0.0.1" {
		t.Fatalf("remote IP = %s, want 127.0.0.1", got)
	}
}

func TestResolverDialerUsesOriginPortForStaticServiceTarget(t *testing.T) {
	var dialed string
	res := resolver.New(resolver.Config{Resolve: []resolver.ResolveEntry{{
		Host: "origin.test", Port: "443", IP: net.ParseIP("192.0.2.10"),
	}}})
	dialer := NewResolverDialer(res, time.Second)
	dialer.BaseDial = func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		conn, peer := net.Pipe()
		_ = peer.Close()
		return conn, nil
	}

	result, err := dialer.Dial(context.Background(), DialRequest{
		Network: "tcp", Host: "edge.test", Port: "8443",
		OriginHost: "origin.test", OriginPort: "0443",
	})
	if err != nil {
		t.Fatal(err)
	}
	result.Conn.Close()
	if dialed != "192.0.2.10:443" {
		t.Fatalf("dial address = %q, want 192.0.2.10:443", dialed)
	}
}

func TestResolverDialerPreservesCandidatePreferenceAndClosesLoser(t *testing.T) {
	first := net.ParseIP("2001:db8::1")
	second := net.ParseIP("192.0.2.1")
	var mu sync.Mutex
	var attempted []string
	loserClosed := make(chan struct{})

	result, err := NewResolverDialer(nil, time.Second).Dial(context.Background(), DialRequest{
		Candidates: []net.IPAddr{{IP: first}, {IP: second}},
		Host:       "service.test",
		Port:       "443",
		Attempt: func(ctx context.Context, _ string, ip net.IPAddr) (net.Conn, error) {
			mu.Lock()
			attempted = append(attempted, ip.IP.String())
			mu.Unlock()
			client, peer := net.Pipe()
			if ip.IP.Equal(first) {
				go func() {
					_, _ = peer.Read(make([]byte, 1))
					close(loserClosed)
				}()
				<-ctx.Done()
				return client, nil
			}
			peer.Close()
			return client, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result.Conn.Close()
	select {
	case <-loserClosed:
	case <-time.After(time.Second):
		t.Fatal("losing connection was not closed after cancellation")
	}
	mu.Lock()
	got := slices.Clone(attempted)
	mu.Unlock()
	if len(got) != 2 || got[0] != first.String() || got[1] != second.String() {
		t.Fatalf("attempt order = %v, want [%s %s]", got, first, second)
	}
}

func TestResolverDialerConnectBudgetIncludesAttempt(t *testing.T) {
	budget := 40 * time.Millisecond
	start := time.Now()
	_, err := NewResolverDialer(nil, 0).Dial(context.Background(), DialRequest{
		Candidates: []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}},
		Host:       "service.test",
		Port:       "443",
		Timeout:    budget,
		Attempt: func(ctx context.Context, _ string, _ net.IPAddr) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	var timeoutErr net.Error
	if !errors.As(err, &timeoutErr) || !timeoutErr.Timeout() {
		t.Fatalf("error = %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("dial took %s, budget was %s", elapsed, budget)
	}
}

func TestResolverDialerUnixSocketUsesSingleAttempt(t *testing.T) {
	var calls int
	result, err := NewResolverDialer(nil, time.Second).Dial(context.Background(), DialRequest{
		Mode:       DialUnix,
		UnixSocket: "/tmp/fetch-test.sock",
		Attempt: func(context.Context, string, net.IPAddr) (net.Conn, error) {
			calls++
			conn, peer := net.Pipe()
			peer.Close()
			return conn, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result.Conn.Close()
	if calls != 1 {
		t.Fatalf("Unix attempts = %d, want 1", calls)
	}
}
