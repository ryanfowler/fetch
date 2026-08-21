package resolver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLookupIPAddrDOHReturnsAAndAAAA(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			queries = append(queries, r.URL.Query().Get("type"))
			if r.Header.Get("Accept") != "application/dns-json" {
				t.Errorf("Accept = %q, want application/dns-json", r.Header.Get("Accept"))
			}
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

func TestLookupDOHTypeReturnsTTL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"Status":0,"Answer":[{"type":1,"data":"127.0.0.1","TTL":123}]}`)
	}))
	defer server.Close()

	records, err := LookupDOHType(context.Background(), mustURL(t, server.URL), "example.com", "A", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %v, want 1 record", records)
	}
	if got, want := records[0].IP.String(), "127.0.0.1"; got != want {
		t.Fatalf("IP = %q, want %q", got, want)
	}
	if got, want := records[0].TTL, 123; got != want {
		t.Fatalf("TTL = %d, want %d", got, want)
	}
}

func TestDOHWireFormatIsAttemptedBeforeJSON(t *testing.T) {
	var post, get int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			post++
			if got := r.Header.Get("Content-Type"); got != "application/dns-message" {
				t.Errorf("Content-Type = %q", got)
			}
			if got := r.Header.Get("Accept"); got != "application/dns-message" {
				t.Errorf("Accept = %q", got)
			}
			query, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			message, err := DecodeMessage(query)
			if err != nil || len(message.Questions) != 1 {
				t.Errorf("query = %v, %v", message, err)
				return
			}
			answer := makeRecord(message.Questions[0].Name, message.Questions[0].Type, []byte{127, 0, 0, 1})
			answer.TTL = 30
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(responsePacket(query, message.Header.ID, message.Questions[0], []Record{answer}))
		case http.MethodGet:
			get++
			t.Errorf("JSON fallback was used for a wire-capable endpoint")
		}
	}))
	defer server.Close()

	records, err := LookupDOHType(context.Background(), mustURL(t, server.URL), "example.com", "A", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].IP.String() != "127.0.0.1" {
		t.Fatalf("records = %#v", records)
	}
	if post != 1 || get != 0 {
		t.Fatalf("POST/GET = %d/%d, want 1/0", post, get)
	}
}

func TestDOHJSONFallbackIsBoundedAndAdjustsAge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		w.Header().Set("Age", "7")
		io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com","type":1,"data":"192.0.2.1","TTL":10},{"name":"example.com","type":1,"data":"192.0.2.2","TTL":0},{"name":"example.com","type":1,"data":"192.0.2.3"}]}`)
	}))
	defer server.Close()

	records, err := LookupDOHType(context.Background(), mustURL(t, server.URL), "example.com", "A", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("records = %#v", records)
	}
	if records[0].TTL != 3 || !records[0].TTLPresent {
		t.Fatalf("adjusted TTL = %#v, want 3/present", records[0])
	}
	if records[1].TTL != 0 || !records[1].TTLPresent {
		t.Fatalf("explicit zero TTL = %#v, want 0/present", records[1])
	}
	if records[2].TTL != 0 || records[2].TTLPresent {
		t.Fatalf("absent TTL = %#v, want 0/absent", records[2])
	}
}

func TestDOHDoesNotFallbackAfterMalformedWireResponse(t *testing.T) {
	var gets int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets++
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write([]byte{1, 2, 3})
	}))
	defer server.Close()

	_, err := LookupDOHType(context.Background(), mustURL(t, server.URL), "example.com", "A", dnsTypeA)
	if err == nil || !strings.Contains(err.Error(), "invalid DoH wire response") {
		t.Fatalf("err = %v, want malformed wire error", err)
	}
	if gets != 0 {
		t.Fatal("malformed wire response incorrectly triggered JSON fallback")
	}
}

func TestDOHErrorExcerptIsBoundedAndTerminalSafe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "bad\x1b[2J"+strings.Repeat("x", 20<<10))
	}))
	defer server.Close()

	_, err := LookupDOHType(context.Background(), mustURL(t, server.URL), "example.com", "A", dnsTypeA)
	if err == nil || strings.Contains(err.Error(), "\x1b") || !strings.Contains(err.Error(), `\x1b`) {
		t.Fatalf("err = %q, want escaped bounded excerpt", err)
	}
	if len(err.Error()) > 17<<10 {
		t.Fatalf("error length = %d, want bounded", len(err.Error()))
	}
}

func TestDOHProtocolFallbackIncludesNotImplemented(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
		io.WriteString(w, `{"Status":0,"Answer":[{"type":1,"data":"192.0.2.10","TTL":4}]}`)
	}))
	defer server.Close()

	records, err := LookupDOHType(context.Background(), mustURL(t, server.URL), "example.com", "A", dnsTypeA)
	if err != nil || len(records) != 1 || records[0].IP.String() != "192.0.2.10" {
		t.Fatalf("records = %#v, err = %v", records, err)
	}
}

func TestDOHAgeOverflowSaturates(t *testing.T) {
	if got := subtractAge(30, parseAge("999999999999999999999999999999")); got != 0 {
		t.Fatalf("overflow Age produced TTL %d, want 0", got)
	}
	if got := subtractAge(30, parseAge("7, 8")); got != 23 {
		t.Fatalf("list-valued Age produced TTL %d, want 23", got)
	}
}

func TestDOHFallbackSharesOneOperationTimeout(t *testing.T) {
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			return &http.Response{StatusCode: http.StatusUnsupportedMediaType, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	client, err := NewDOHClient(DOHConfig{
		ServerURL:    mustURL(t, "https://resolver.test/dns-query"),
		RoundTripper: transport,
		Timeout:      20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = client.LookupType(context.Background(), "example.com", "A", dnsTypeA)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("fallback timeout took %s", elapsed)
	}
}

func TestDOHInjectedRoundTripperUsesTimeout(t *testing.T) {
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	client, err := NewDOHClient(DOHConfig{
		ServerURL:    mustURL(t, "https://resolver.test/dns-query"),
		RoundTripper: transport,
		Timeout:      20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = client.LookupType(context.Background(), "example.com", "A", dnsTypeA)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

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
