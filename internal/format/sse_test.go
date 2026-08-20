package format

import (
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestStreamEventsEmitsBeforeEOF(t *testing.T) {
	release := make(chan struct{})
	reader := &blockingReader{data: []byte("data: {\"ready\":true}\n\n"), release: release}
	events := make(chan event, 1)
	errs := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev, err := range streamEvents(reader) {
			if err != nil {
				errs <- err
				return
			}
			events <- ev
		}
	}()

	select {
	case ev := <-events:
		if ev.Data != `{"ready":true}` {
			t.Fatalf("event data = %q, want ready event", ev.Data)
		}
	case err := <-errs:
		t.Fatalf("streamEvents() error = %v", err)
	case <-time.After(time.Second):
		close(release)
		t.Fatal("streamEvents waited for EOF before emitting the event")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("streamEvents did not finish after EOF")
	}
}

func TestStreamEventsHandlesChunkedCRLFAndJSONData(t *testing.T) {
	input := &chunkReader{chunks: [][]byte{
		[]byte("event: message\r"), []byte("\ndata: {\"n\":"), []byte("1}\r\n"), []byte("\r\n"),
	}}
	p := core.TestPrinter(false)
	if err := FormatEventStream(input, p); err != nil {
		t.Fatalf("FormatEventStream() error = %v", err)
	}
	want := "[message]\n{ \"n\": 1 }\n"
	if got := string(p.Bytes()); got != want {
		t.Fatalf("FormatEventStream() = %q, want %q", got, want)
	}
}

func TestStreamEventsRejectsAnOversizedEvent(t *testing.T) {
	input := strings.NewReader("data: " + strings.Repeat("x", int(maxStreamingRecordBytes)) + "\n\n")
	for _, err := range streamEvents(input) {
		if err == nil {
			continue
		}
		return
	}
	t.Fatal("streamEvents() accepted an oversized event")
}

func TestStreamEventsEOFDispatchesFinalEventWithoutBlankLine(t *testing.T) {
	got := collectStreamEvents(t, "data: final\n")
	want := []event{
		{
			Type: "message",
			Data: "final",
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("streamEvents() = %#v, want %#v", got, want)
	}
}

func TestStreamEventsEOFDoesNotDuplicateFinalEventWithBlankLine(t *testing.T) {
	got := collectStreamEvents(t, "data: final\n\n")
	want := []event{
		{
			Type: "message",
			Data: "final",
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("streamEvents() = %#v, want %#v", got, want)
	}
}

type blockingReader struct {
	data    []byte
	release <-chan struct{}
}

func (r *blockingReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	<-r.release
	return 0, io.EOF
}

func collectStreamEvents(t *testing.T, input string) []event {
	t.Helper()

	var events []event
	for ev, err := range streamEvents(strings.NewReader(input)) {
		if err != nil {
			t.Fatalf("streamEvents() returned error: %v", err)
		}
		events = append(events, ev)
	}
	return events
}
