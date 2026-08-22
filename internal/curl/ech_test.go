package curl

import "testing"

func TestParseECHModes(t *testing.T) {
	for _, test := range []struct {
		value string
		want  string
	}{
		{"hard", "hard"},
		{"true", "true"},
		{"auto", "auto"},
		{"false", "false"},
	} {
		result, err := Parse("curl --ech " + test.value + " https://example.com")
		if err != nil {
			t.Fatalf("Parse(%q): %v", test.value, err)
		}
		if result.ECH != test.want {
			t.Errorf("ECH = %q, want %q", result.ECH, test.want)
		}
	}
}

func TestParseRejectsUnsupportedECHMode(t *testing.T) {
	if _, err := Parse("curl --ech maybe https://example.com"); err == nil {
		t.Fatal("expected unsupported ECH mode to fail")
	}
}
