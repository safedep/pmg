//go:build linux

package proxyserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunnerGlob(t *testing.T) {
	assert.Equal(t, "/home/runner/actions-runner/bin/Runner.*", runnerGlob("/home/runner/actions-runner/bin/Runner.Worker"))
}

func TestParentPIDReadsProc(t *testing.T) {
	ppid, err := parentPID(os.Getpid())
	require.NoError(t, err)
	assert.Equal(t, os.Getppid(), ppid)
}

func TestFindAncestorExecutableFindsSelf(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)

	got, ok := findAncestorExecutable(os.Getpid(), filepath.Base(exe))
	require.True(t, ok)
	assert.Equal(t, exe, got)

	_, ok = findAncestorExecutable(os.Getpid(), "pmg-no-such-ancestor")
	assert.False(t, ok)
}

func TestRunnerExemptGlobsOutsideActions(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	assert.Nil(t, RunnerExemptGlobs())
}

func TestProcessRunningSeesSelf(t *testing.T) {
	comm, err := os.ReadFile("/proc/self/comm")
	require.NoError(t, err)
	assert.True(t, processRunning(strings.TrimSpace(string(comm))))
	assert.False(t, processRunning("pmg-no-such-process"))
}
