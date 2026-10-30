package image

import "testing"

func TestDetectRex(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want emulator
	}{
		{
			name: "term program",
			env:  map[string]string{"TERM_PROGRAM": "rex"},
			want: eRex,
		},
		{
			name: "term program overrides inherited terminal",
			env: map[string]string{
				"TERM_PROGRAM":    "rex",
				"TERM":            "xterm-ghostty",
				"GHOSTTY_BIN_DIR": "/ghostty",
			},
			want: eRex,
		},
		{
			name: "custom variable",
			env:  map[string]string{"REX_BIN_DIR": "/rex"},
			want: eRex,
		},
		{
			name: "custom variable overrides inherited ghostty variable",
			env: map[string]string{
				"REX_BIN_DIR":     "/rex",
				"GHOSTTY_BIN_DIR": "/ghostty",
			},
			want: eRex,
		},
		{
			name: "zellij overrides rex",
			env: map[string]string{
				"ZELLIJ":       "1",
				"TERM_PROGRAM": "rex",
				"REX_BIN_DIR":  "/rex",
			},
			want: eZellij,
		},
		{
			name: "tmux overrides inherited rex variable",
			env: map[string]string{
				"TERM_PROGRAM": "tmux",
				"REX_BIN_DIR":  "/rex",
			},
			want: eTmux,
		},
		{
			name: "unknown",
			want: eUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, key := range []string{
				"TERM_PROGRAM", "TERM", "ZELLIJ", "REX_BIN_DIR",
				"GHOSTTY_BIN_DIR", "ITERM_SESSION_ID", "KITTY_PID",
				"KONSOLE_VERSION", "VSCODE_INJECTION", "WEZTERM_EXECUTABLE", "WT_SESSION",
			} {
				t.Setenv(key, "")
			}
			for key, value := range tt.env {
				t.Setenv(key, value)
			}
			if got := detectEmulator(); got != tt.want {
				t.Fatalf("detectEmulator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRexProtocol(t *testing.T) {
	if got := eRex.Protocol(); got != protoKitty {
		t.Fatalf("Rex protocol = %v, want %v", got, protoKitty)
	}
}
