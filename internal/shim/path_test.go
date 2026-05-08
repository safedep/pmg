package shim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestResolveRealBinary(t *testing.T) {
	tmpDir := t.TempDir()
	pmgBinDir := filepath.Join(tmpDir, ".pmg", "bin")
	realBinDir := filepath.Join(tmpDir, "real-bin")
	require.NoError(t, os.MkdirAll(pmgBinDir, 0o755))
	require.NoError(t, os.MkdirAll(realBinDir, 0o755))

	// Create a fake shim in pmg bin
	shimPath := filepath.Join(pmgBinDir, "npm")
	require.NoError(t, os.WriteFile(shimPath, []byte("#!/bin/sh\necho shim"), 0o755))

	// Create a fake real binary
	realPath := filepath.Join(realBinDir, "npm")
	require.NoError(t, os.WriteFile(realPath, []byte("#!/bin/sh\necho real"), 0o755))

	// Set PATH with pmg bin first (simulating shim setup)
	t.Setenv("PATH", pmgBinDir+":"+realBinDir)

	resolved, err := ResolveRealBinary("npm")
	require.NoError(t, err)
	assert.Equal(t, realPath, resolved)
}

func TestFilterPMGFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		env      []string
		expected []string
	}{
		{
			name: "filters PATH entry",
			env: []string{
				"HOME=/home/user",
				"PATH=/home/user/.pmg/bin:/usr/local/bin:/usr/bin",
				"SHELL=/bin/zsh",
			},
			expected: []string{
				"HOME=/home/user",
				"PATH=/usr/local/bin:/usr/bin",
				"SHELL=/bin/zsh",
			},
		},
		{
			name: "no PATH entry",
			env: []string{
				"HOME=/home/user",
				"SHELL=/bin/zsh",
			},
			expected: []string{
				"HOME=/home/user",
				"SHELL=/bin/zsh",
			},
		},
		{
			name:     "empty env",
			env:      []string{},
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := FilterPMGFromEnv(tc.env)
			assert.Equal(t, tc.expected, result)
		})
	}
}
