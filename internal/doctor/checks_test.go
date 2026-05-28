package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateProtectionResult(t *testing.T) {
	tests := []struct {
		name       string
		pm         string
		pkg        string
		err        error
		wantStatus CheckStatus
	}{
		{
			name:       "blocked",
			pm:         "npm",
			pkg:        "safedep-test-pkg@0.1.3",
			err:        fmt.Errorf("exit status 1"),
			wantStatus: StatusPass,
		},
		{
			name:       "not blocked",
			pm:         "npm",
			pkg:        "safedep-test-pkg@0.1.3",
			err:        nil,
			wantStatus: StatusFail,
		},
		{
			name:       "pm not found",
			pm:         "npm",
			pkg:        "safedep-test-pkg@0.1.3",
			err:        &exec.Error{Name: "npm", Err: exec.ErrNotFound},
			wantStatus: StatusWarn,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateProtectionResult(tt.pm, tt.pkg, tt.err)
			assert.Equal(t, tt.wantStatus, result.Status)
		})
	}
}

func TestProtectionTestCases(t *testing.T) {
	cases := ProtectionTestCases()
	require.GreaterOrEqual(t, len(cases), 2)

	hasNpm := false
	hasPip := false
	for _, tc := range cases {
		if tc.PackageManager == "npm" {
			hasNpm = true
			assert.False(t, tc.NeedsVenv)
			assert.Contains(t, tc.InstallArgs, "--no-cache")
			assert.Contains(t, tc.InstallArgs, "--prefer-online")
		}
		if tc.PackageManager == "pip" {
			hasPip = true
			assert.True(t, tc.NeedsVenv)
			assert.Contains(t, tc.InstallArgs, "--no-cache-dir")
		}
	}
	assert.True(t, hasNpm)
	assert.True(t, hasPip)
}

func TestPrependPath(t *testing.T) {
	env := []string{"HOME=/home/user", "PATH=/usr/bin:/bin", "TERM=xterm"}
	result := prependPath(env, "/tmp/venv/bin")

	require.Len(t, result, 3)
	assert.Equal(t, "HOME=/home/user", result[0])
	assert.True(t, strings.HasPrefix(result[1], "PATH=/tmp/venv/bin"))
	assert.Contains(t, result[1], "/usr/bin:/bin")
	assert.Equal(t, "TERM=xterm", result[2])
}

func TestSetupVenv(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}

	tmpDir := t.TempDir()
	venvDir, err := setupVenv(tmpDir)
	require.NoError(t, err)

	pipPath := filepath.Join(venvDir, "bin", "pip")
	_, err = os.Stat(pipPath)
	assert.NoError(t, err)
}

func TestCheckShimScripts(t *testing.T) {
	tmpDir := t.TempDir()
	shimDir := filepath.Join(tmpDir, ".pmg", "bin")
	require.NoError(t, os.MkdirAll(shimDir, 0o755))

	shimPath := filepath.Join(shimDir, "npm")
	require.NoError(t, os.WriteFile(shimPath, []byte("#!/bin/sh\nexec pmg npm \"$@\""), 0o755))

	found, missing := CheckShimScripts(shimDir, []string{"npm", "pip"})
	assert.Equal(t, []string{"npm"}, found)
	assert.Equal(t, []string{"pip"}, missing)
}
