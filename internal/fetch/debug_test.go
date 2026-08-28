package fetch

import (
	"crypto/tls"
	"net"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

// TestDebugTrace_ConcurrentHappyEyeballs simulates Go's default Happy
// Eyeballs behavior: two dials race on parallel goroutines and their
// httptrace ConnectStart/ConnectDone hooks fire concurrently. The metrics
// struct must stay consistent (run with -race).
func TestDebugTrace_ConcurrentHappyEyeballs(t *testing.T) {
	trace, m := newDebugTrace(nil)

	// Read the metrics from a separate goroutine while the hooks run.
	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
				m.snapshot()
			}
		}
	}()

	var dialsWG sync.WaitGroup
	dialsWG.Add(2)
	loserStarted := make(chan struct{})
	releaseLoser := make(chan struct{})
	winnerDone := make(chan struct{})

	// Losing IPv6 dial: starts first and completes after the winner. This
	// makes a late successful callback observable without sleeping.
	go func() {
		defer dialsWG.Done()
		trace.ConnectStart("tcp6", "[::1]:443")
		close(loserStarted)
		<-releaseLoser
		trace.ConnectDone("tcp6", "[::1]:443", nil)
	}()
	<-loserStarted

	// Winning IPv4 dial: its successful callback commits the TCP duration.
	go func() {
		defer dialsWG.Done()
		trace.ConnectStart("tcp4", "127.0.0.1:443")
		trace.ConnectDone("tcp4", "127.0.0.1:443", nil)
		close(winnerDone)
	}()
	<-winnerDone

	snap := m.snapshot()
	winnerDuration := snap.tcpDur
	close(releaseLoser)
	dialsWG.Wait()
	close(stop)
	readerWG.Wait()
	snap = m.snapshot()

	if snap.tcpStart.IsZero() {
		t.Fatal("expected tcpStart to be recorded")
	}
	// The late successful loser must not replace the winner's duration.
	if winnerDuration <= 0 {
		t.Fatalf("expected positive tcpDur, got %v", winnerDuration)
	}
	if snap.tcpDur != winnerDuration {
		t.Errorf("late dial changed tcpDur from %v to %v", winnerDuration, snap.tcpDur)
	}

	m.mu.Lock()
	outstanding := len(m.tcpDials)
	m.mu.Unlock()
	if outstanding != 0 {
		t.Errorf("expected no outstanding dial starts, got %d", outstanding)
	}
}

func TestDebugTraceReportsKeyExchange(t *testing.T) {
	p := core.TestPrinter(false)
	trace, _ := newDebugTrace(p)

	trace.TLSHandshakeStart()
	trace.TLSHandshakeDone(tls.ConnectionState{
		Version: tls.VersionTLS13,
		CurveID: tls.X25519MLKEM768,
	}, nil)

	if got := string(p.Bytes()); !strings.Contains(got, "Key exchange: X25519MLKEM768") {
		t.Fatalf("debug output omitted negotiated key exchange: %q", got)
	}
}

func TestDebugTrace_GetConnResetsRedirectHop(t *testing.T) {
	trace, m := newDebugTrace(nil)

	trace.GetConn("first.example:443")
	trace.DNSStart(httptrace.DNSStartInfo{Host: "first.example"})
	trace.DNSDone(httptrace.DNSDoneInfo{})
	trace.ConnectStart("tcp", "127.0.0.1:443")
	trace.ConnectDone("tcp", "127.0.0.1:443", nil)
	trace.TLSHandshakeStart()
	trace.TLSHandshakeDone(tls.ConnectionState{}, nil)
	trace.GetConn("second.example:443")

	snap := m.snapshot()
	if !snap.dnsStart.IsZero() || !snap.tcpStart.IsZero() || !snap.tlsStart.IsZero() {
		t.Fatal("expected connection timings to reset for a new redirect hop")
	}
	if snap.dnsDur != 0 || snap.tcpDur != 0 || snap.tlsDur != 0 {
		t.Fatal("expected connection durations to reset for a new redirect hop")
	}
}

func TestDebugTrace_GotConnAndTTFB(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on localhost: %v", err)
	}
	defer ln.Close()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			connCh <- c
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("cannot dial localhost: %v", err)
	}
	defer client.Close()
	serverConn := <-connCh
	defer serverConn.Close()

	trace, m := newDebugTrace(nil)
	trace.GotConn(httptrace.GotConnInfo{Conn: client})

	snap := m.snapshot()
	if snap.reused {
		t.Error("expected reused=false")
	}
	if snap.remoteIP == "" {
		t.Error("expected remoteIP to be extracted from connection")
	}
	if ip := net.ParseIP(snap.remoteIP); ip == nil {
		t.Errorf("expected valid IP in remoteIP, got %q", snap.remoteIP)
	}

	// GotFirstResponseByte runs after GotConn, potentially on another
	// goroutine; it must read ttfbStart safely.
	done := make(chan struct{})
	go func() {
		defer close(done)
		trace.GotFirstResponseByte()
	}()
	<-done

	snap = m.snapshot()
	if snap.ttfbStart.IsZero() {
		t.Fatal("expected ttfbStart to be recorded")
	}
	if snap.ttfbDur < 0 {
		t.Errorf("expected non-negative ttfbDur, got %v", snap.ttfbDur)
	}
}

func TestDebugTrace_TTFBWithoutGotConn(t *testing.T) {
	trace, m := newDebugTrace(nil)
	trace.GotFirstResponseByte()

	snap := m.snapshot()
	if !snap.ttfbStart.IsZero() {
		t.Error("expected ttfbStart to remain unset")
	}
	if snap.ttfbDur != 0 {
		t.Errorf("expected ttfbDur to remain 0, got %v", snap.ttfbDur)
	}
}
