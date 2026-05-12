package format

import (
	"reflect"
	"strings"
	"testing"
)

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
