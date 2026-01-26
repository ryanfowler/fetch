package fetch

import (
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple filename",
			input:    "file.txt",
			expected: "file.txt",
			wantErr:  false,
		},
		{
			name:     "path traversal with ../ prefix",
			input:    "../file.txt",
			expected: "file.txt",
			wantErr:  false,
		},
		{
			name:     "path traversal with multiple ../ prefixes",
			input:    "../../../tmp/file.txt",
			expected: "file.txt",
			wantErr:  false,
		},
		{
			name:     "absolute path",
			input:    "/tmp/file.txt",
			expected: "file.txt",
			wantErr:  false,
		},
		{
			name:     "nested path",
			input:    "dir/subdir/file.txt",
			expected: "file.txt",
			wantErr:  false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "single dot",
			input:    ".",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "double dot",
			input:    "..",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "hidden file",
			input:    ".hidden",
			expected: ".hidden",
			wantErr:  false,
		},
		{
			name:     "path with trailing slash",
			input:    "dir/",
			expected: "dir",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sanitizeFilename(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("sanitizeFilename(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("sanitizeFilename(%q) unexpected error: %v", tt.input, err)
				return
			}
			if result != tt.expected {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
