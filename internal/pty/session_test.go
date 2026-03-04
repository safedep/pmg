package pty

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsInteractiveTerminal(t *testing.T) {
	tests := []struct {
		name     string
		ciEnv    string
		expected bool
	}{
		{
			name:     "returns false when CI env is set to true",
			ciEnv:    "true",
			expected: false,
		},
		{
			name:     "returns false when CI env is set to TRUE (case insensitive)",
			ciEnv:    "TRUE",
			expected: false,
		},
		{
			name:     "returns false when CI env is set to True (mixed case)",
			ciEnv:    "True",
			expected: false,
		},
		{
			name:     "returns false in test runner (stdin/stdout are pipes)",
			ciEnv:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ciEnv != "" {
				t.Setenv("CI", tt.ciEnv)
			} else {
				t.Setenv("CI", "")
			}

			result := IsInteractiveTerminal()
			assert.Equal(t, tt.expected, result)
		})
	}
}
