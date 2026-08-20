package body

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestReplayableBytesAndPreview(t *testing.T) {
	b := NewBytes([]byte("hello"), "text/plain")

	preview, err := b.Preview(3)
	if err != nil {
		t.Fatal(err)
	}
	if string(preview.Data) != "hel" || !preview.Truncated {
		t.Fatalf("preview = %#v, want hel/truncated", preview)
	}

	first, err := b.Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(first)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	if string(got) != "hello" {
		t.Fatalf("first body = %q, want hello", got)
	}

	replay, err := b.Replay()
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(replay)
	if err != nil {
		t.Fatal(err)
	}
	replay.Close()
	if string(got) != "hello" {
		t.Fatalf("replay body = %q, want hello", got)
	}
}

func TestOneShotPreviewPreservesTheEntireBody(t *testing.T) {
	b := NewReader(strings.NewReader("abcdef"), -1, "")
	preview, err := b.Preview(3)
	if err != nil {
		t.Fatal(err)
	}
	if string(preview.Data) != "abc" || !preview.Truncated {
		t.Fatalf("preview = %#v, want abc/truncated", preview)
	}

	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcdef" {
		t.Fatalf("body after preview = %q, want abcdef", got)
	}
	if _, err := b.Replay(); !errors.Is(err, ErrNotReplayable) {
		t.Fatalf("Replay error = %v, want ErrNotReplayable", err)
	}
}

func TestFileBodyRejectsTruncationAndReplacement(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/body.txt"
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := NewFile(path, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Replay(); err == nil {
		t.Fatal("Replay succeeded after file replacement/truncation")
	}
}

func TestMaterializeIsBoundedAndReplayable(t *testing.T) {
	b := NewReader(strings.NewReader("12345"), -1, "")
	if _, err := b.Materialize(4); !errors.Is(err, core.ErrLimitExceeded) {
		t.Fatalf("Materialize error = %v, want a limit error", err)
	}

	b = NewReader(strings.NewReader("1234"), -1, "")
	got, err := b.Materialize(4)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1234" || !b.Replayable() || b.ContentLength() != 4 {
		t.Fatalf("materialized body = %q, replayable=%v, length=%d", got, b.Replayable(), b.ContentLength())
	}
}

func TestStreamForwardsProgressCounter(t *testing.T) {
	source := &progressReadCloser{Reader: strings.NewReader("payload"), total: 7}
	stream := NewStream(source)
	counter, ok := stream.ProgressBytes()
	if !ok || counter != 7 {
		t.Fatalf("ProgressBytes() = %d, %v; want 7, true", counter, ok)
	}
}

func TestStreamTeeReadsOnceAndClosesSource(t *testing.T) {
	var observed bytes.Buffer
	source := &trackingReadCloser{Reader: strings.NewReader("payload")}
	stream := NewStream(source)
	stream.AddTee(&observed)
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload" || observed.String() != "payload" {
		t.Fatalf("got=%q observed=%q", got, observed.String())
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if !source.closed {
		t.Fatal("stream did not close its source")
	}
}

type progressReadCloser struct {
	io.Reader
	total int64
}

func (r *progressReadCloser) Close() error { return nil }

func (r *progressReadCloser) ProgressBytes() (int64, bool) { return r.total, true }

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}
