package fetch

import (
	"testing"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestWebsocketInteractive(t *testing.T) {
	tests := []struct {
		name          string
		mode          core.WSInteractiveMode
		terminals     bool
		bodyFromStdin bool
		want          bool
		wantErr       bool
	}{
		{"auto with terminals", core.WSInteractiveAuto, true, false, true, false},
		{"auto without terminals", core.WSInteractiveAuto, false, false, false, false},
		{"auto with body from stdin", core.WSInteractiveAuto, true, true, false, false},
		{"on with terminals", core.WSInteractiveOn, true, false, true, false},
		{"on without terminals", core.WSInteractiveOn, false, false, false, true},
		{"on with body from stdin", core.WSInteractiveOn, true, true, false, true},
		{"off", core.WSInteractiveOff, true, false, false, false},
		{"off with body from stdin", core.WSInteractiveOff, true, true, false, false},
	}
	for _, tt := range tests {
		got, err := websocketInteractive(tt.mode, tt.terminals, tt.bodyFromStdin)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("%s: websocketInteractive() = %t, %v; want %t, error %t", tt.name, got, err, tt.want, tt.wantErr)
		}
	}
}
