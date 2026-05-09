package resolver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"testing"
)

func TestLookupIPAddrDOHReturnsAAndAAAA(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("type"))
		if r.Header.Get("Accept") != "application/dns-json" {
			t.Errorf("Accept = %q, want application/dns-json", r.Header.Get("Accept"))
		}

		switch r.URL.Query().Get("type") {
		case "A":
			io.WriteString(w, `{"Status":0,"Answer":[{"type":5,"data":"alias.example"},{"type":1,"data":"127.0.0.1"}]}`)
		case "AAAA":
			io.WriteString(w, `{"Status":0,"Answer":[{"type":28,"data":"::1"}]}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	u := mustURL(t, server.URL+"/dns-query")
	addrs, err := New(Config{Server: u}).LookupIPAddr(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}

	if got, want := ipStrings(addrs), []string{"127.0.0.1", "::1"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("addrs = %v, want %v", got, want)
	}
	if got, want := strings.Join(queries, ","), "A,AAAA"; got != want {
		t.Fatalf("queries = %q, want %q", got, want)
	}
}

func TestLookupIPAddrDOHNXDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"Status":3}`)
	}))
	defer server.Close()

	_, err := New(Config{Server: mustURL(t, server.URL)}).LookupIPAddr(context.Background(), "missing.example")
	if err == nil || !strings.Contains(err.Error(), "NXDomain") {
		t.Fatalf("err = %v, want NXDomain", err)
	}
}

func TestLookupIPAddrDoesNotTraceIPLiteral(t *testing.T) {
	var started bool
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			started = true
		},
	})

	addrs, err := New(Config{}).LookupIPAddr(ctx, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if started {
		t.Fatal("DNS trace started for IP literal")
	}
	if got := ipStrings(addrs); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("addrs = %v, want [127.0.0.1]", got)
	}
}

func TestLookupIPAddrDOHTraceHooks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"Status":0,"Answer":[{"type":1,"data":"127.0.0.1"}]}`)
	}))
	defer server.Close()

	var startedHost string
	var doneAddrs []net.IPAddr
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			startedHost = info.Host
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			doneAddrs = info.Addrs
		},
	})

	_, err := New(Config{Server: mustURL(t, server.URL)}).LookupIPAddr(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if startedHost != "example.com" {
		t.Fatalf("DNSStart host = %q, want example.com", startedHost)
	}
	if got := ipStrings(doneAddrs); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("DNSDone addrs = %v, want [127.0.0.1]", got)
	}
}

func TestDialContextUsesResolvedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
		close(accepted)
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "A":
			fmt.Fprintf(w, `{"Status":0,"Answer":[{"type":1,"data":"127.0.0.1"}]}`)
		case "AAAA":
			io.WriteString(w, `{"Status":3}`)
		}
	}))
	defer server.Close()

	conn, err := New(Config{Server: mustURL(t, server.URL)}).DialContext(context.Background(), "tcp", net.JoinHostPort("example.com", port))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	<-accepted
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func ipStrings(addrs []net.IPAddr) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.IP.String())
	}
	return out
}
