package format

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
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
			return err
		}

		if written {
			p.WriteString("\n")
		} else {
			written = true
		}

		writeEventStreamType(ev.Type, p)
		writeEventStreamData(ev.Data, p)
	}
	return nil
}

func writeEventStreamType(t string, p *core.Printer) {
	p.WriteString("[")
	p.Set(core.Bold)
	p.WriteString(t)
	p.Reset()
	p.WriteString("]\n")
	p.Flush()
}

func writeEventStreamData(d string, p *core.Printer) {
	dec := json.NewDecoder(strings.NewReader(d))
	if formatNDJSONValue(dec, p) == nil {
		// Ensure there are no more tokens in the event.
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			p.WriteString("\n")
			p.Flush()
			return
		}
	}

	p.Reset()
	p.WriteString(d)
	p.WriteString("\n")
	p.Flush()
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
// io.Reader.
func streamEvents(r io.Reader) iter.Seq2[event, error] {
	return func(yield func(event, error) bool) {
		scanner := bufio.NewScanner(r)
		scanner.Split(splitEndOfLine)

		var seenLine bool
		var eventType string
		var sb strings.Builder
		var lastEventID string
		for scanner.Scan() {
			line := scanner.Bytes()
			if !seenLine {
				line = bytes.TrimPrefix(line, bomBytes)
				seenLine = true
			}

			if len(line) == 0 {
				// Empty line, dispatch the ev.
				ev := event{
					LastID: lastEventID,
					Type:   eventType,
					Data:   sb.String(),
				}
				ev.Data = strings.TrimSuffix(ev.Data, "\n")

				eventType = ""
				sb.Reset()

				if ev.Data == "" {
					// Empty data, return.
					continue
				}

				if ev.Type == "" {
					ev.Type = "message"
				}
				if !yield(ev, nil) {
					return
				}
				continue
			}

			name, value, _ := bytes.Cut(line, colonBytes)
			if len(name) == 0 {
				// This is a comment, ignore it.
				continue
			}
			value = bytes.TrimPrefix(value, spaceBytes)

			if bytes.Equal(name, eventBytes) {
				eventType = string(value)
			} else if bytes.Equal(name, dataBytes) {
				sb.Grow(len(value) + 1)
				sb.Write(value)
				sb.WriteByte('\n')
			} else if bytes.Equal(name, idBytes) {
				lastEventID = string(value)
			}
		}
		if err := scanner.Err(); err != nil {
			yield(event{}, err)
		}
	}
}

// splitEndOfLine splits on \n, \r, or \r\n.
func splitEndOfLine(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	for i := range data {
		switch data[i] {
		case '\n':
			// If previous char was CR, drop it from the token.
			if i > 0 && data[i-1] == '\r' {
				return i + 1, data[:i-1], nil
			}
			return i + 1, data[:i], nil
		case '\r':
			// If CR is followed by LF, skip both.
			if i+1 < len(data) && data[i+1] == '\n' {
				return i + 2, data[:i], nil
			}
			return i + 1, data[:i], nil
		}
	}

	if atEOF {
		return len(data), data, nil
	}

	return 0, nil, nil
}
