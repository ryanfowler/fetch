package complete

import (
	"strings"
	"testing"

	"github.com/ryanfowler/fetch/internal/cli"
)

func TestCompleteBash(t *testing.T) {
	var app cli.App
	flags := app.CLI().Flags
	_, long := getFlagMaps(flags)

	tests := []struct {
		name  string
		shell Shell
		args  []string
		exp   string
	}{
		{
			name:  "should return nothing when no args",
			shell: Bash{},
			args:  nil,
			exp:   "",
		},
		{
			name:  "should return nothing when only arg is command",
			shell: Bash{},
			args:  []string{"fetch"},
			exp:   "",
		},
		{
			name:  "should complete color flag",
			shell: Bash{},
			args:  []string{"fetch", "--col"},
			exp:   "--color \n",
		},
		{
			name:  "should complete color value",
			shell: Bash{},
			args:  []string{"fetch", "--color", ""},
			exp: func() string {
				var sb strings.Builder
				for _, kv := range long["color"].Values {
					sb.WriteString(kv.Key)
					sb.WriteString(" \n")
				}
				return sb.String()
			}(),
		},
		{
			name:  "should complete color value with prefix",
			shell: Bash{},
			args:  []string{"fetch", "--color", "o"},
			exp: func() string {
				var sb strings.Builder
				for _, kv := range long["color"].Values {
					if !strings.HasPrefix(kv.Key, "o") {
						continue
					}
					sb.WriteString(kv.Key)
					sb.WriteString(" \n")
				}
				return sb.String()
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := Complete(test.shell, test.args)
			if res != test.exp {
				t.Fatalf("Unexpected result:\n%s", res)
			}
		})
	}
}

func TestCompleteFish(t *testing.T) {
	var app cli.App
	flags := app.CLI().Flags
	_, long := getFlagMaps(flags)

	tests := []struct {
		name  string
		shell Shell
		args  []string
		exp   string
	}{
		{
			name:  "should return nothing when no args",
			shell: Fish{},
			args:  nil,
			exp:   "",
		},
		{
			name:  "should return nothing when only arg is command",
			shell: Fish{},
			args:  []string{"fetch"},
			exp:   "",
		},
		{
			name:  "should complete color flag",
			shell: Fish{},
			args:  []string{"fetch", "--col"},
			exp:   "--color\t" + long["color"].Description + "\n",
		},
		{
			name:  "should complete color value",
			shell: Fish{},
			args:  []string{"fetch", "--color", ""},
			exp: func() string {
				var sb strings.Builder
				for _, kv := range long["color"].Values {
					sb.WriteString(kv.Key)
					sb.WriteByte('\t')
					sb.WriteString(kv.Val)
					sb.WriteByte('\n')
				}
				return sb.String()
			}(),
		},
		{
			name:  "should complete color value with prefix",
			shell: Fish{},
			args:  []string{"fetch", "--color", "o"},
			exp: func() string {
				var sb strings.Builder
				for _, kv := range long["color"].Values {
					if !strings.HasPrefix(kv.Key, "o") {
						continue
					}
					sb.WriteString(kv.Key)
					sb.WriteByte('\t')
					sb.WriteString(kv.Val)
					sb.WriteByte('\n')
				}
				return sb.String()
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := Complete(test.shell, test.args)
			if res != test.exp {
				t.Fatalf("Unexpected result:\n%s", res)
			}
		})
	}
}

func TestPowerShellCompletion(t *testing.T) {
	if shell := GetShell("powershell"); shell == nil {
		t.Fatal("PowerShell completion is not registered")
	}
	got := Complete(PowerShell{}, []string{"fetch", "--comp"})
	if !strings.Contains(got, "--compress\t") || !strings.Contains(got, "--complete\t") {
		t.Fatalf("PowerShell completion = %q", got)
	}
	got = Complete(PowerShell{}, []string{"fetch", "--color", ""})
	if !strings.Contains(got, "auto\t") {
		t.Fatalf("PowerShell value completion after a trailing space = %q", got)
	}
	register := (PowerShell{}).Register()
	if !strings.Contains(register, "Register-ArgumentCompleter") ||
		!strings.Contains(register, "EndOffset -le $cursorPosition") ||
		!strings.Contains(register, "@('--complete=powershell', '--') + $elements") {
		t.Fatalf("PowerShell registration script is invalid: %q", register)
	}
}

func TestCompleteCLI002AliasesAndValues(t *testing.T) {
	got := Complete(Bash{}, []string{"fetch", "--http"})
	for _, want := range []string{"--http ", "--http1 ", "--http2 ", "--http3 "} {
		if !strings.Contains(got, want) {
			t.Fatalf("HTTP completion %q does not contain %q", got, want)
		}
	}
	if got := Complete(Bash{}, []string{"fetch", "--http1", ""}); got != "" {
		t.Fatalf("fixed HTTP alias offered values: %q", got)
	}

	got = Complete(Bash{}, []string{"fetch", "--install-skill", ""})
	for _, want := range []string{"auto", "agents", "codex", "claude", "gemini", "pi", "all"} {
		if !strings.Contains(got, want) {
			t.Fatalf("skill completion %q does not contain %q", got, want)
		}
	}
}
