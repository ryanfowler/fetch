package ws

import (
	"reflect"
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestSanitizeMessageText(t *testing.T) {
	got := sanitizeMessageText("ok\x1b[31m\r\nbad\x00\tend")
	want := `ok\x1b[31m` + "\n" + `bad\x00    end`
	if got != want {
		t.Fatalf("sanitizeMessageText() = %q, want %q", got, want)
	}
}

func TestWrapDisplayLines(t *testing.T) {
	tests := []struct {
		name  string
		input string
		width int
		want  []string
	}{
		{
			name:  "wraps ascii",
			input: "abcdef",
			width: 3,
			want:  []string{"abc", "def"},
		},
		{
			name:  "preserves explicit newlines",
			input: "ab\ncd",
			width: 8,
			want:  []string{"ab", "cd"},
		},
		{
			name:  "wide runes count as two cells",
			input: "日本語",
			width: 4,
			want:  []string{"日本", "語"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapDisplayLines(tt.input, tt.width)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("wrapDisplayLines() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestInteractiveMessageRowCount(t *testing.T) {
	im := &interactiveMode{
		cfg:  Config{Format: core.FormatOff},
		rows: 12,
		cols: 7,
	}

	msg := messageEntry{arrow: "←", data: []byte("abcdef")}
	if got, want := im.messageRowCount(msg), 3; got != want {
		t.Fatalf("messageRowCount() = %d, want %d", got, want)
	}

	msg = messageEntry{arrow: "←", data: []byte("ab\ncd")}
	if got, want := im.messageRowCount(msg), 3; got != want {
		t.Fatalf("messageRowCount() = %d, want %d", got, want)
	}
}
