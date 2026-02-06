package update

import "testing"

func TestIsVersionTag(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"v1.2.3", true},
		{"v0.0.0", true},
		{"v10.20.30", true},
		{"v100.200.300", true},
		{"v(dev)", false},
		{"v0.0.0-20231215164305-abcdef123456", false},
		{"1.2.3", false},
		{"v1.2", false},
		{"v1.2.3.4", false},
		{"v.1.2", false},
		{"v1..2", false},
		{"v1.2.", false},
		{"", false},
		{"v", false},
		{"vx.y.z", false},
		{"v1.2.3-rc1", false},
		{"v1.2.3+meta", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isVersionTag(tt.input); got != tt.want {
				t.Errorf("isVersionTag(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
