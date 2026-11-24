package complete

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/cli"
	"github.com/ryanfowler/fetch/internal/core"
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

func TestBashCandidate(t *testing.T) {
	tests := map[string]string{
		"--data":            "--data",
		"@dir/file.json":    "@dir/file.json",
		"a b.txt":           `a\ b.txt`,
		"*":                 `\*`,
		"$(touch pwned)":    `\$\(touch\ pwned\)`,
		"./$(touch pwned)/": `./\$\(touch\ pwned\)/`,
		"it's":              `it\'s`,
		"~/":                "~/",
		"@~/":               "@~/",
		"~/x y":             `~/x\ y`,
		"$HOME/a b.txt":     `$HOME/a\ b.txt`,
		"~root":             `\~root`,
		"#x":                `\#x`,
		"dir/~x#y":          "dir/~x#y",
		"a~b#c":             "a~b#c",
		"key=value&other":   `key=value\&other`,
		"@my dir/sub dir/":  `@my dir/sub\ dir/`,
	}
	for input, want := range tests {
		got, ok := bashCandidate(input)
		if !ok || got != want {
			t.Errorf("bashCandidate(%q) = %q, %t, want %q", input, got, ok, want)
		}
	}
	for _, input := range []string{"line\nbreak", "tab\there", "del\x7f"} {
		if _, ok := bashCandidate(input); ok {
			t.Errorf("bashCandidate(%q) accepted a control character", input)
		}
	}
}

// TestBashCandidateRoundTrip checks that bash reads each escaped file name
// back as the original name.
func TestBashCandidateRoundTrip(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	var names []string
	for c := byte(0x20); c < 0x7f; c++ {
		if c == '/' {
			continue
		}
		names = append(names, string(c), "a"+string(c)+"b")
	}
	var script strings.Builder
	for _, name := range names {
		word, ok := bashCandidate("dir/" + name)
		if !ok {
			t.Fatalf("bashCandidate rejected %q", name)
		}
		script.WriteString("printf '%s\\0' " + word + "\n")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "--norc", "--noprofile", "-c", script.String())
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"HOME=" + cmd.Dir, "PATH=" + os.Getenv("PATH")}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bash: %v", err)
	}
	got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if len(got) != len(names) {
		t.Fatalf("bash printed %d words, want %d", len(got), len(names))
	}
	for i, name := range names {
		if got[i] != "dir/"+name {
			t.Errorf("bash read %q as %q", name, got[i])
		}
	}
}

func TestBashComplete(t *testing.T) {
	got := Bash{}.Complete([]core.KeyVal[string]{
		{Key: "a b.txt"},
		{Key: "my dir/"},
		{Key: "--header="},
		{Key: "bad\nname"},
	})
	want := "a\\ b.txt \nmy\\ dir/\n--header=\n"
	if got != want {
		t.Errorf("Bash.Complete = %q, want %q", got, want)
	}
}

func TestPowerShellQuote(t *testing.T) {
	tests := map[string]string{
		"--data":                   "--data",
		"dir/file.json":            "dir/file.json",
		"@file.json":               "'@file.json'",
		"a b.txt":                  "'a b.txt'",
		"$(touch pwned)":           "'$(touch pwned)'",
		"it's":                     "'it''s'",
		"it\u2019s.txt":            "'it\u2019\u2019s.txt'",
		"a\u2019 ; calc ; \u2018b": "'a\u2019\u2019 ; calc ; \u2018\u2018b'",
	}
	for input, want := range tests {
		if got := powerShellQuote(input); got != want {
			t.Errorf("powerShellQuote(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPowerShellComplete(t *testing.T) {
	got := PowerShell{}.Complete([]core.KeyVal[string]{
		{Key: "a b.txt", Val: "File"},
		{Key: "--data"},
		{Key: "bad\nname", Val: "File"},
	})
	want := "'a b.txt'\tFile\n--data\n"
	if got != want {
		t.Errorf("PowerShell.Complete = %q, want %q", got, want)
	}
}

func TestBashRegisterDoesNotExpandCandidates(t *testing.T) {
	script := Bash{}.Register()
	if strings.Contains(script, "COMPREPLY=($(") {
		t.Fatal("the bash script splits and glob-expands candidates")
	}
	if !strings.Contains(script, "read -r") {
		t.Fatal("the bash script does not read candidates line by line")
	}
}
