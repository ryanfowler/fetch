package format

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

// FormatEventStream formats the provided stream of server sent events to the
// Printer, flushing after each event.
func FormatEventStream(r io.Reader, p *core.Printer) error {
	var written bool
	for ev, err := range streamEvents(r) {
		if err != nil {
			p.Discard()
			return err
		}

		if written {
			p.WriteString("\n")
		} else {
			written = true
		}

		if err := writeEventStreamType(ev.Type, p); err != nil {
			return err
		}
		if err := writeEventStreamData(ev.Data, p); err != nil {
			return err
		}
	}
	return nil
}

func writeEventStreamType(t string, p *core.Printer) error {
	p.WriteString("[")
	p.Set(core.Bold)
	p.WriteStringUntrusted(t)
	p.Reset()
	p.WriteString("]\n")
	return p.Flush()
}

func writeEventStreamData(d string, p *core.Printer) error {
	dec := jsontext.NewDecoder(strings.NewReader(d))
	if formatNDJSONValue(dec, p) == nil {
		// Ensure there are no more tokens in the event.
		_, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			p.WriteString("\n")
			return p.Flush()
		}
	}

	p.Discard()
	p.WriteStringUntrusted(d)
	p.WriteString("\n")
	return p.Flush()
}

var (
	bomBytes   = []byte("\xEF\xBB\xBF")
	colonBytes = []byte(":")
	spaceBytes = []byte(" ")

	dataBytes  = []byte("data")
	eventBytes = []byte("event")
	idBytes    = []byte("id")
)

type event struct {
	LastID string
	Type   string
	Data   string
}

// streamEvents returns an iterator of server sent events from the provided
// io.Reader. Events are yielded at each blank line, so a live stream does not
// wait for EOF before emitting completed events.
func streamEvents(r io.Reader) iter.Seq2[event, error] {
	return func(yield func(event, error) bool) {
		lines := newLineReader(r)
		var seenLine bool
		var eventType string
		var data bytes.Buffer
		var lastEventID string
		var eventBytesPending int64
		lineNumber := 0

		dispatch := func() bool {
			ev := event{
				LastID: lastEventID,
				Type:   eventType,
				Data:   strings.TrimSuffix(data.String(), "\n"),
			}

			eventType = ""
			data.Reset()
			eventBytesPending = 0

			if ev.Data == "" {
				return true
			}
			if ev.Type == "" {
				ev.Type = "message"
			}
			return yield(ev, nil)
		}

		for {
			line, ok, err := lines.next()
			if err != nil {
				yield(event{}, fmt.Errorf("invalid SSE event near line %d: %w", lineNumber+1, err))
				return
			}
			if !ok {
				break
			}
			lineNumber++
			if !seenLine {
				line = bytes.TrimPrefix(line, bomBytes)
				seenLine = true
			}

			if len(line) == 0 {
				if !dispatch() {
					return
				}
				continue
			}
			eventBytesPending += int64(len(line) + lines.lineEndingBytes())
			if eventBytesPending > maxStreamingRecordBytes {
				yield(event{}, fmt.Errorf("SSE event exceeds %d-byte limit: %w", maxStreamingRecordBytes, ErrStreamingLimit))
				return
			}

			name, value, _ := bytes.Cut(line, colonBytes)
			if len(name) == 0 {
				continue
			}
			value = bytes.TrimPrefix(value, spaceBytes)

			switch {
			case bytes.Equal(name, eventBytes):
				eventType = string(value)
			case bytes.Equal(name, dataBytes):
				_, _ = data.Write(value)
				_ = data.WriteByte('\n')
			case bytes.Equal(name, idBytes):
				lastEventID = string(value)
			}
		}

		if data.Len() > 0 {
			dispatch()
		}
	}
}
