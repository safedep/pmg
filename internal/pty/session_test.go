package pty

import (
	"context"
	"testing"

	"github.com/safedep/ptyx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Without this the field can stop at the PMG layer and no other test notices.
func TestSessionConfigCmdLineReachesSpawnOpts(t *testing.T) {
	cfg := SessionConfig{
		Command: `C:\Windows\System32\cmd.exe`,
		CmdLine: `cmd.exe /d /s /v:off /c ""C:\npm.cmd" install lodash"`,
		Env:     []string{"A=B"},
	}

	assert.Equal(t, ptyx.SpawnOpts{
		Prog:    cfg.Command,
		CmdLine: cfg.CmdLine,
		Cols:    120,
		Rows:    40,
		Env:     cfg.Env,
	}, cfg.spawnOpts(120, 40))
}

func TestNewSessionRejectsCmdLineWithArgs(t *testing.T) {
	// The guard runs before the console opens, so this holds without a TTY.
	_, err := NewSession(context.Background(), SessionConfig{
		Command: "cmd.exe",
		Args:    []string{"/c", "dir"},
		CmdLine: `cmd.exe /c dir`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CmdLine or Args, not both")
}
