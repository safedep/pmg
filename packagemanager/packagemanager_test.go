package packagemanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsFirstNonFlagArgInList(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		list     []string
		expected bool
	}{
		{
			name:     "exact match on first arg",
			args:     []string{"list", "express"},
			list:     []string{"list", "show"},
			expected: true,
		},
		{
			name:     "no match",
			args:     []string{"install", "express"},
			list:     []string{"list", "show"},
			expected: false,
		},
		{
			name:     "flags before subcommand are skipped",
			args:     []string{"--global", "list"},
			list:     []string{"list"},
			expected: true,
		},
		{
			name:     "only first non-flag arg is checked",
			args:     []string{"install", "list"},
			list:     []string{"list"},
			expected: false,
		},
		{
			name:     "empty args",
			args:     []string{},
			list:     []string{"list"},
			expected: false,
		},
		{
			name:     "empty list",
			args:     []string{"list"},
			list:     []string{},
			expected: false,
		},
		{
			name:     "all flags no subcommand",
			args:     []string{"--verbose", "-g", "--save"},
			list:     []string{"list"},
			expected: false,
		},
		{
			name:     "short flag before subcommand",
			args:     []string{"-g", "list"},
			list:     []string{"list"},
			expected: true,
		},
		{
			name:     "package name matches list entry but is second arg",
			args:     []string{"install", "dev"},
			list:     []string{"dev"},
			expected: false,
		},
		{
			name:     "partial match does not count",
			args:     []string{"listing"},
			list:     []string{"list"},
			expected: false,
		},
		{
			name:     "case sensitive",
			args:     []string{"List"},
			list:     []string{"list"},
			expected: false,
		},
		{
			name:     "npm run script matching skip command",
			args:     []string{"run", "dev"},
			list:     []string{"run"},
			expected: true,
		},
		{
			name:     "flag-like value after subcommand is irrelevant",
			args:     []string{"install", "--save", "express"},
			list:     []string{"install"},
			expected: true,
		},
		{
			name:     "real world: npm ls",
			args:     []string{"ls"},
			list:     []string{"ls", "list", "outdated", "why", "explain"},
			expected: true,
		},
		{
			name:     "real world: pip install is not in non-download list",
			args:     []string{"install", "requests"},
			list:     []string{"list", "show", "freeze", "check"},
			expected: false,
		},
		{
			name:     "real world: pip list",
			args:     []string{"list", "--outdated"},
			list:     []string{"list", "show", "freeze", "check"},
			expected: true,
		},
		{
			name:     "flag with value before subcommand",
			args:     []string{"--registry", "https://registry.npmjs.org", "list"},
			list:     []string{"list"},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsFirstNonFlagArgInList(tc.args, tc.list)
			assert.Equal(t, tc.expected, result)
		})
	}
}
