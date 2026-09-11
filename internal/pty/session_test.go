package pty

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/safedep/ptyx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingConsole struct {
	events *[]string
}

func (c *recordingConsole) In() io.Reader    { return nil }
func (c *recordingConsole) Out() io.Writer   { return io.Discard }
func (c *recordingConsole) Err() *os.File    { return nil }
func (c *recordingConsole) IsATTYOut() bool  { return true }
func (c *recordingConsole) Size() (int, int) { return 80, 24 }
func (c *recordingConsole) MakeRaw() (ptyx.RawState, error) {
	*c.events = append(*c.events, "make-raw")
	return struct{}{}, nil
}
func (c *recordingConsole) Restore(ptyx.RawState) error {
	*c.events = append(*c.events, "restore-input")
	return nil
}
func (c *recordingConsole) EnableVT() {
	*c.events = append(*c.events, "enable-vt")
}
func (c *recordingConsole) OnResize() <-chan struct{} { return nil }
func (c *recordingConsole) Close() error {
	*c.events = append(*c.events, "close")
	return nil
}

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

func TestSetCookedModeRestoresInputAndOutputModes(t *testing.T) {
	var events []string
	sess := &session{
		console:  &recordingConsole{events: &events},
		oldState: struct{}{},
		restoreOutput: func() error {
			events = append(events, "restore-output")
			return nil
		},
	}

	require.NoError(t, sess.SetCookedMode())
	assert.Equal(t, []string{"restore-input", "restore-output"}, events)
}

func TestSetRawModeEnablesVTAfterInputIsRaw(t *testing.T) {
	var events []string
	sess := &session{console: &recordingConsole{events: &events}}

	require.NoError(t, sess.SetRawMode())
	assert.Equal(t, []string{"make-raw", "enable-vt"}, events)
}

func TestSetCookedModeReportsOutputRestoreError(t *testing.T) {
	var events []string
	sess := &session{
		console:       &recordingConsole{events: &events},
		oldState:      struct{}{},
		restoreOutput: func() error { return assert.AnError },
	}

	err := sess.SetCookedMode()
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestPrepareConsoleCapturesOutputBeforeCreation(t *testing.T) {
	var events []string
	console := &recordingConsole{events: &events}

	got, restoreOutput, err := prepareConsole(
		func() func() error {
			events = append(events, "capture-output")
			return func() error {
				events = append(events, "restore-output")
				return nil
			}
		},
		func() (ptyx.Console, error) {
			events = append(events, "create-console")
			return console, nil
		},
	)

	require.NoError(t, err)
	assert.Same(t, console, got)
	assert.Equal(t, []string{"capture-output", "create-console"}, events)

	require.NoError(t, restoreOutput())
	assert.Equal(t, []string{"capture-output", "create-console", "restore-output"}, events)
}
