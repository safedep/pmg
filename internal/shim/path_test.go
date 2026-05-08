package shim

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterPMGFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "removes pmg bin from middle",
			path:     "/usr/local/bin:/home/user/.pmg/bin:/usr/bin",
			expected: "/usr/local/bin:/usr/bin",
		},
		{
			name:     "removes pmg bin from start",
			path:     "/home/user/.pmg/bin:/usr/local/bin:/usr/bin",
			expected: "/usr/local/bin:/usr/bin",
		},
		{
			name:     "removes pmg bin from end",
			path:     "/usr/local/bin:/usr/bin:/home/user/.pmg/bin",
			expected: "/usr/local/bin:/usr/bin",
		},
		{
			name:     "no pmg bin present",
			path:     "/usr/local/bin:/usr/bin",
			expected: "/usr/local/bin:/usr/bin",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "",
		},
		{
			name:     "only pmg bin",
			path:     "/home/user/.pmg/bin",
			expected: "",
		},
		{
			name:     "does not remove partial matches",
			path:     "/usr/local/bin:/home/user/.pmg/binaries:/usr/bin",
			expected: "/usr/local/bin:/home/user/.pmg/binaries:/usr/bin",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := FilterPMGFromPath(tc.path)
			assert.Equal(t, tc.expected, result)
		})
	}
}
