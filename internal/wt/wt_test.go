package wt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/ryanfowler/fetch/internal/core"
)

type fakeSession struct {
	stream      *fakeStream
	datagrams   [][]byte
	received    [][]byte
	sendErr     error
	receiveGate <-chan struct{}
	sendReady   chan struct{}
	sendTarget  int
	sendOnce    sync.Once
}

func (s *fakeSession) OpenStream(context.Context) (io.ReadWriteCloser, error) { return s.stream, nil }
func (s *fakeSession) SendDatagram(p []byte) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.datagrams = append(s.datagrams, append([]byte(nil), p...))
	if s.sendReady != nil && len(s.datagrams) == s.sendTarget {
		s.sendOnce.Do(func() { close(s.sendReady) })
	}
	return nil
}
func (s *fakeSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if s.receiveGate != nil {
		select {
		case <-s.receiveGate:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
		s.receiveGate = nil
	}
	if len(s.received) == 0 {
		return nil, errors.New("done")
	}
	p := s.received[0]
	s.received = s.received[1:]
	return p, nil
}
func (s *fakeSession) Close() error { return nil }

type fakeStream struct {
	bytes.Buffer
	input    []byte
	closed   bool
	maxWrite int
}

func (s *fakeStream) Read(p []byte) (int, error) {
	if len(s.input) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.input)
	s.input = s.input[n:]
	return n, nil
}
func (s *fakeStream) Write(p []byte) (int, error) {
	if s.maxWrite > 0 && len(p) > s.maxWrite {
		p = p[:s.maxWrite]
	}
	return s.Buffer.Write(p)
}
func (s *fakeStream) Close() error { s.closed = true; return nil }

func TestRunStreamDefersInputAndReadsAfterEOF(t *testing.T) {
	s := &fakeSession{stream: &fakeStream{input: []byte("reply")}}
	var out bytes.Buffer
	err := Run(context.Background(), Config{Session: s, Stdout: &out, InitialReader: strings.NewReader("first"), Stdin: strings.NewReader("second")})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.stream.String(); got != "firstsecond" {
		t.Fatalf("sent %q", got)
	}
	if out.String() != "reply" {
		t.Fatalf("received %q", out.String())
	}
	if !s.stream.closed {
		t.Fatal("stream was not closed for writing")
	}
}

func TestRunDatagramsUsesOneInitialPayloadAndJSONLines(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ready := make(chan struct{})
	s := &fakeSession{received: [][]byte{{0, 1}, {}}, receiveGate: ready, sendReady: ready, sendTarget: 3}
	var out bytes.Buffer
	err := Run(ctx, Config{Session: s, Stdout: &out, Mode: core.WTDatagram, InitialReader: strings.NewReader("a\nb"), Stdin: strings.NewReader("one\ntwo\n")})
	if err == nil {
		t.Fatal("expected receive loop error")
	}
	if len(s.datagrams) != 3 || string(s.datagrams[0]) != "a\nb" || string(s.datagrams[1]) != "one" || string(s.datagrams[2]) != "two" {
		t.Fatalf("datagrams %#v", s.datagrams)
	}
	want := "{\"sequence\":0,\"length\":2,\"data\":\"AAE=\"}\n{\"sequence\":1,\"length\":0,\"data\":\"\"}\n"
	if out.String() != want {
		t.Fatalf("output %q, want %q", out.String(), want)
	}
}

func TestRunStreamCompletesShortWrites(t *testing.T) {
	s := &fakeSession{stream: &fakeStream{maxWrite: 2}}
	var out bytes.Buffer
	err := Run(context.Background(), Config{Session: s, Stdout: &out, InitialPayloadSet: true, InitialPayload: []byte("first"), InitialReader: strings.NewReader("second")})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.stream.String(); got != "firstsecond" {
		t.Fatalf("sent %q", got)
	}
}

func TestRunStreamRejectsShortOutputWrite(t *testing.T) {
	s := &fakeSession{stream: &fakeStream{input: []byte("reply")}}
	err := Run(context.Background(), Config{Session: s, Stdout: &shortWriter{}})
	if !errors.Is(err, io.ErrShortWrite) || !strings.Contains(err.Error(), "stream output") {
		t.Fatalf("got %v", err)
	}
}

type writeFailureStream struct {
	closed <-chan struct{}
	err    error
}

func (s *writeFailureStream) Read([]byte) (int, error) {
	<-s.closed
	return 0, s.err
}

func (s *writeFailureStream) Write([]byte) (int, error) { return 0, nil }
func (s *writeFailureStream) Close() error              { return nil }

type writeFailureSession struct {
	stream *writeFailureStream
	closed chan struct{}
	once   sync.Once
}

func (s *writeFailureSession) OpenStream(context.Context) (io.ReadWriteCloser, error) {
	return s.stream, nil
}
func (s *writeFailureSession) SendDatagram([]byte) error { return nil }
func (s *writeFailureSession) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, errors.New("unused")
}
func (s *writeFailureSession) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func TestRunStreamPreservesInitiatingWriteError(t *testing.T) {
	closed := make(chan struct{})
	readErr := errors.New("session closed after write failure")
	s := &writeFailureSession{closed: closed, stream: &writeFailureStream{closed: closed, err: readErr}}
	err := Run(context.Background(), Config{Session: s, Stdout: io.Discard, InitialPayloadSet: true, InitialPayload: []byte("payload")})
	if !errors.Is(err, io.ErrNoProgress) || errors.Is(err, readErr) {
		t.Fatalf("got %v", err)
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return w.Buffer.Write(p[:len(p)-1])
}

type blockingReadCloser struct {
	closed chan struct{}
	once   sync.Once
}

func (r *blockingReadCloser) Read([]byte) (int, error) {
	<-r.closed
	return 0, errors.New("input closed")
}

func (r *blockingReadCloser) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

func TestRunStreamFlushErrorCancelsBlockingInput(t *testing.T) {
	s := &fakeSession{stream: &fakeStream{input: []byte{0xe2}}}
	stdin := &blockingReadCloser{closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), Config{Session: s, Stdout: &shortWriter{}, Stdin: stdin, TerminalOutput: true})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrNoProgress) || !strings.Contains(err.Error(), "stream output") {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run blocked after terminal output flush error")
	}
}

func TestReceiveDatagramsRejectsShortOutputWrite(t *testing.T) {
	s := &fakeSession{received: [][]byte{{0, 1}}}
	err := receiveDatagrams(context.Background(), Config{Session: s, Stdout: &shortWriter{}})
	if !errors.Is(err, io.ErrShortWrite) || !strings.Contains(err.Error(), "datagram output") {
		t.Fatalf("got %v", err)
	}
}

func TestSendInputDatagramsHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &fakeSession{}
	err := sendInputDatagrams(ctx, s, strings.NewReader("payload"), core.WTDatagramBinary)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if len(s.datagrams) != 0 {
		t.Fatalf("sent datagrams after cancellation: %#v", s.datagrams)
	}
}

func TestRunDatagramsDoesNotSendInitialDataAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, cfg := range []Config{
		{InitialPayloadSet: true, InitialPayload: []byte("payload")},
		{InitialReader: strings.NewReader("payload")},
	} {
		s := &fakeSession{}
		cfg.Session = s
		cfg.Stdout = io.Discard
		cfg.Mode = core.WTDatagram
		err := Run(ctx, cfg)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
		if len(s.datagrams) != 0 {
			t.Fatalf("sent datagrams after cancellation: %#v", s.datagrams)
		}
	}
}

type peerCloseSession struct {
	fakeSession
	closed chan struct{}
	once   sync.Once
	err    error
}

func (s *peerCloseSession) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, s.err
}

func (s *peerCloseSession) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

type waitReader struct{ ready <-chan struct{} }

func (r waitReader) Read(p []byte) (int, error) {
	<-r.ready
	return copy(p, "payload"), io.EOF
}

func TestRunDatagramsPreservesPeerCloseError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	peerErr := errors.New("peer closed session")
	s := &peerCloseSession{fakeSession: fakeSession{}, closed: make(chan struct{}), err: peerErr}
	err := Run(ctx, Config{Session: s, Stdout: io.Discard, Mode: core.WTDatagram, DatagramMode: core.WTDatagramBinary, Stdin: waitReader{ready: s.closed}})
	if !errors.Is(err, peerErr) {
		t.Fatalf("got %v, want %v", err, peerErr)
	}
	if len(s.datagrams) != 0 {
		t.Fatalf("sent datagrams after peer close: %#v", s.datagrams)
	}
}

func TestSendDatagramReportsCurrentQUICLimit(t *testing.T) {
	s := &fakeSession{sendErr: &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1180}}
	err := sendDatagram(s, make([]byte, 1200))
	if err == nil || !strings.Contains(err.Error(), "1200 bytes; current QUIC limit 1180 bytes before HTTP/3 overhead") {
		t.Fatalf("got %v", err)
	}
}

func TestTerminalWriterEscapesControlsAndKeepsUTF8(t *testing.T) {
	var out bytes.Buffer
	w := &terminalWriter{dst: &out}
	if _, err := w.Write([]byte{0xe2}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte{0x82, 0xac, 0x1b}); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "€\\x1b" {
		t.Fatalf("output %q", out.String())
	}
}
