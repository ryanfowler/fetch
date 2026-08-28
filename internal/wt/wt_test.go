package wt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

type fakeSession struct {
	stream    *fakeStream
	datagrams [][]byte
	received  [][]byte
}

func (s *fakeSession) OpenStream(context.Context) (io.ReadWriteCloser, error) { return s.stream, nil }
func (s *fakeSession) SendDatagram(p []byte) error {
	s.datagrams = append(s.datagrams, append([]byte(nil), p...))
	return nil
}
func (s *fakeSession) ReceiveDatagram(context.Context) ([]byte, error) {
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
	input  []byte
	closed bool
}

func (s *fakeStream) Read(p []byte) (int, error) {
	if len(s.input) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.input)
	s.input = s.input[n:]
	return n, nil
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
	s := &fakeSession{received: [][]byte{{0, 1}, {}}}
	var out bytes.Buffer
	err := Run(context.Background(), Config{Session: s, Stdout: &out, Mode: core.WTDatagram, InitialReader: strings.NewReader("a\nb"), Stdin: strings.NewReader("one\ntwo\n")})
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
