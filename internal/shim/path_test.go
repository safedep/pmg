package shim

import (
	"os"
	"path/filepath"
	"strings"
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
	tests := []struct {
		name      string
		setupDirs func(t *testing.T, tmpDir string) (pmgBin, realBin string)
		binary    string
		wantPath  func(realBinDir string) string
		wantErr   bool
	}{
		{
			name: "skips shim and finds real binary",
			setupDirs: func(t *testing.T, tmpDir string) (string, string) {
				pmgBin := filepath.Join(tmpDir, ".pmg", "bin")
				realBin := filepath.Join(tmpDir, "real-bin")
				require.NoError(t, os.MkdirAll(pmgBin, 0o755))
				require.NoError(t, os.MkdirAll(realBin, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(pmgBin, "npm"), []byte("#!/bin/sh\necho shim"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(realBin, "npm"), []byte("#!/bin/sh\necho real"), 0o755))
				return pmgBin, realBin
			},
			binary:   "npm",
			wantPath: func(realBin string) string { return filepath.Join(realBin, "npm") },
		},
		{
			name: "returns error when binary not found outside shim dir",
			setupDirs: func(t *testing.T, tmpDir string) (string, string) {
				pmgBin := filepath.Join(tmpDir, ".pmg", "bin")
				realBin := filepath.Join(tmpDir, "real-bin")
				require.NoError(t, os.MkdirAll(pmgBin, 0o755))
				require.NoError(t, os.MkdirAll(realBin, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(pmgBin, "npm"), []byte("#!/bin/sh\necho shim"), 0o755))
				return pmgBin, realBin
			},
			binary:  "npm",
			wantErr: true,
		},
		{
			name: "works when no shim dir exists in PATH",
			setupDirs: func(t *testing.T, tmpDir string) (string, string) {
				realBin := filepath.Join(tmpDir, "real-bin")
				require.NoError(t, os.MkdirAll(realBin, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(realBin, "npm"), []byte("#!/bin/sh\necho real"), 0o755))
				return "", realBin
			},
			binary:   "npm",
			wantPath: func(realBin string) string { return filepath.Join(realBin, "npm") },
		},
		{
			name: "resolves correct binary when multiple exist",
			setupDirs: func(t *testing.T, tmpDir string) (string, string) {
				pmgBin := filepath.Join(tmpDir, ".pmg", "bin")
				firstBin := filepath.Join(tmpDir, "first-bin")
				secondBin := filepath.Join(tmpDir, "second-bin")
				require.NoError(t, os.MkdirAll(pmgBin, 0o755))
				require.NoError(t, os.MkdirAll(firstBin, 0o755))
				require.NoError(t, os.MkdirAll(secondBin, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(pmgBin, "npm"), []byte("#!/bin/sh\necho shim"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(firstBin, "npm"), []byte("#!/bin/sh\necho first"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(secondBin, "npm"), []byte("#!/bin/sh\necho second"), 0o755))
				return pmgBin, firstBin + ":" + secondBin
			},
			binary:   "npm",
			wantPath: func(realBin string) string { return filepath.Join(filepath.SplitList(realBin)[0], "npm") },
		},
		{
			name: "restores original PATH after resolution",
			setupDirs: func(t *testing.T, tmpDir string) (string, string) {
				pmgBin := filepath.Join(tmpDir, ".pmg", "bin")
				realBin := filepath.Join(tmpDir, "real-bin")
				require.NoError(t, os.MkdirAll(pmgBin, 0o755))
				require.NoError(t, os.MkdirAll(realBin, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(pmgBin, "npm"), []byte("#!/bin/sh\necho shim"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(realBin, "npm"), []byte("#!/bin/sh\necho real"), 0o755))
				return pmgBin, realBin
			},
			binary:   "npm",
			wantPath: func(realBin string) string { return filepath.Join(realBin, "npm") },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			pmgBin, realBin := tc.setupDirs(t, tmpDir)

			var pathParts []string
			if pmgBin != "" {
				pathParts = append(pathParts, pmgBin)
			}
			pathParts = append(pathParts, filepath.SplitList(realBin)...)

			t.Setenv("PATH", strings.Join(pathParts, ":"))
			originalPath := os.Getenv("PATH")

			resolved, err := ResolveRealBinary(tc.binary)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantPath(realBin), resolved)

			// Verify PATH was restored
			assert.Equal(t, originalPath, os.Getenv("PATH"), "PATH should be restored after ResolveRealBinary")
		})
	}
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
