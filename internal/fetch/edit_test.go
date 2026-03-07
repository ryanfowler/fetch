package fetch

import (
	"reflect"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "simple command",
			input: "vim",
			want:  []string{"vim"},
		},
		{
			name:  "command with flag",
			input: "code --wait",
			want:  []string{"code", "--wait"},
		},
		{
			name:  "command with multiple flags",
			input: "nvim -f --clean",
			want:  []string{"nvim", "-f", "--clean"},
		},
		{
			name:  "double quoted path",
			input: `"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" --wait`,
			want:  []string{"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code", "--wait"},
		},
		{
			name:  "single quoted path",
			input: `'/usr/local/my editor/bin/edit' -w`,
			want:  []string{"/usr/local/my editor/bin/edit", "-w"},
		},
		{
			name:  "extra whitespace",
			input: "  vim   -f  ",
			want:  []string{"vim", "-f"},
		},
		{
			name:  "tabs as separators",
			input: "vim\t-f\t--clean",
			want:  []string{"vim", "-f", "--clean"},
		},
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "only whitespace",
			input: "   ",
			want:  nil,
		},
		{
			name:  "quoted empty string arg",
			input: `vim ""`,
			want:  []string{"vim"},
		},
		{
			name:  "mixed quotes",
			input: `'/path/to/my editor' "--wait"`,
			want:  []string{"/path/to/my editor", "--wait"},
		},
		{
			name:  "adjacent quotes and text",
			input: `vim --"clean"`,
			want:  []string{"vim", "--clean"},
		},
		{
			name:  "unclosed quote",
			input: `"vim --wait`,
			want:  []string{"vim --wait"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitArgs(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitArgs(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFindEditor(t *testing.T) {
	t.Run("VISUAL takes precedence over EDITOR", func(t *testing.T) {
		t.Setenv("VISUAL", "code --wait")
		t.Setenv("EDITOR", "vim")

		got, ok := findEditor()
		if !ok {
			t.Fatal("findEditor() returned false")
		}
		want := []string{"code", "--wait"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("findEditor() = %v, want %v", got, want)
		}
	})

	t.Run("falls back to EDITOR", func(t *testing.T) {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", "nvim -f")

		got, ok := findEditor()
		if !ok {
			t.Fatal("findEditor() returned false")
		}
		want := []string{"nvim", "-f"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("findEditor() = %v, want %v", got, want)
		}
	})

	t.Run("EDITOR with quoted path", func(t *testing.T) {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", `"/usr/local/my app/bin/edit" --wait`)

		got, ok := findEditor()
		if !ok {
			t.Fatal("findEditor() returned false")
		}
		want := []string{"/usr/local/my app/bin/edit", "--wait"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("findEditor() = %v, want %v", got, want)
		}
	})
}
