package ui

import (
	"testing"
)

// TestTermWidthFormatText is exported for testing
func TestTermWidthFormatTextFunc(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		maxWidth int
		expected string
	}{
		{
			name:     "empty string",
			text:     "",
			maxWidth: 10,
			expected: "",
		},
		{
			name:     "single word less than max width",
			text:     "hello",
			maxWidth: 10,
			expected: "hello",
		},
		{
			name:     "single word longer than max width",
			text:     "supercalifragilisticexpialidocious",
			maxWidth: 10,
			expected: "supercalifragilisticexpialidocious",
		},
		{
			name:     "multiple words on single line",
			text:     "hello world",
			maxWidth: 20,
			expected: "hello world",
		},
		{
			name:     "multiple words wrapped to multiple lines",
			text:     "The quick brown fox jumps over the lazy dog",
			maxWidth: 20,
			expected: "The quick brown fox\njumps over the lazy\ndog",
		},
		{
			name:     "text with existing newlines",
			text:     "hello\nworld",
			maxWidth: 20,
			expected: "hello world",
		},
		{
			name:     "text with multiple spaces",
			text:     "hello  world   test",
			maxWidth: 20,
			expected: "hello world test",
		},
		{
			name:     "very small max width",
			text:     "hello world",
			maxWidth: 3,
			expected: "hello\nworld",
		},
		{
			name:     "large max width",
			text:     "The quick brown fox jumps over the lazy dog",
			maxWidth: 100,
			expected: "The quick brown fox jumps over the lazy dog",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := termWidthFormatText(tt.text, tt.maxWidth)
			if result != tt.expected {
				t.Errorf("termWidthFormatText() = %q, want %q", result, tt.expected)
			}
		})
	}
}
