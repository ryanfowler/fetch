package pager

import (
	"context"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ryanfowler/fetch/internal/core"
)

func TestCommandFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want Command
	}{
		{
			name: "default less flags",
			want: Command{Program: "less", Args: []string{"-FIRX"}, Fallback: true},
		},
		{
			name: "LESS disables default flags",
			env:  map[string]string{"LESS": "-SR"},
			want: Command{Program: "less", Fallback: true},
		},
		{
			name: "quoted pager",
			env:  map[string]string{"PAGER": `"/tmp/my pager" --prompt='fetch > ' --pattern=a\ b`},
			want: Command{Program: "/tmp/my pager", Args: []string{"--prompt=fetch > ", "--pattern=a b"}},
		},
		{
			name: "invalid pager falls back",
			env:  map[string]string{"PAGER": `less "unterminated`},
			want: Command{Program: "less", Args: []string{"-FIRX"}, Fallback: true},
		},
		{
			name: "shell operators are arguments",
			env:  map[string]string{"PAGER": "cat | unexpected"},
			want: Command{Program: "cat", Args: []string{"|", "unexpected"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := CommandFromEnv(func(name string) string { return test.env[name] })
			if got.Program != test.want.Program || got.Fallback != test.want.Fallback || !sameStrings(got.Args, test.want.Args) {
				t.Fatalf("CommandFromEnv() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestShouldPage(t *testing.T) {
	if !ShouldPage(core.PagerAuto, true, false) {
		t.Fatal("auto mode should page terminal output")
	}
	if ShouldPage(core.PagerAuto, false, false) {
		t.Fatal("auto mode should not page redirected output")
	}
	if ShouldPage(core.PagerAuto, true, true) {
		t.Fatal("images should bypass the pager")
	}
	if !ShouldPage(core.PagerOn, false, false) {
		t.Fatal("on mode should page redirected output")
	}
	if ShouldPage(core.PagerOff, true, false) {
		t.Fatal("off mode should not page")
	}
}

func TestStreamContextTerminatesPagerProcessGroup(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("starts a Unix subprocess")
	}
	t.Setenv("PAGER", "sh -c 'sleep 30'")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- StreamContext(ctx, strings.NewReader("help"), core.PagerOn, false, false, io.Discard)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled pager returned nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pager process group did not terminate")
	}
}

func TestSplitWords(t *testing.T) {
	words, err := splitWords(`less --prompt='fetch > ' --pattern=a\ b`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"less", "--prompt=fetch > ", "--pattern=a b"}
	if !sameStrings(words, want) {
		t.Fatalf("splitWords() = %q, want %q", words, want)
	}
	if _, err := splitWords(`less "unterminated`); err == nil {
		t.Fatal("unterminated quote was accepted")
	}
}

func sameStrings(a, b []string) bool {
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}
