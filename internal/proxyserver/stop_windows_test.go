//go:build windows

package proxyserver

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStopGracefullyStopsProcessOnWindows(t *testing.T) {
	if statePath := os.Getenv("PMG_TEST_STOP_CHILD_STATE"); statePath != "" {
		stopCh, cleanup, err := listenStopRequest()
		require.NoError(t, err)
		defer cleanup()

		initial := State{
			PID:  os.Getpid(),
			Addr: "127.0.0.1:18080",
		}
		require.NoError(t, writeState(statePath, initial))

		<-stopCh

		final := initial
		final.BlockedCount = 2
		require.NoError(t, writeState(statePath, final))
		return
	}

	statePath := filepath.Join(t.TempDir(), "proxy-state.json")
	self, err := os.Executable()
	require.NoError(t, err)
	child := exec.Command(self, "-test.run=^TestStopGracefullyStopsProcessOnWindows$")
	child.Env = append(os.Environ(), "PMG_TEST_STOP_CHILD_STATE="+statePath)
	require.NoError(t, child.Start())

	t.Cleanup(func() {
		if child.Process != nil {
			if err := child.Process.Kill(); err != nil {
				t.Logf("kill child: %v", err)
			}
			if err := child.Wait(); err != nil {
				t.Logf("wait child: %v", err)
			}
		}
	})

	require.Eventually(t, func() bool {
		return GetStatus(statePath).Running
	}, 5*time.Second, 20*time.Millisecond, "child process should write state and report running")

	result, err := Stop(statePath)
	require.NoError(t, err)
	assert.Equal(t, child.Process.Pid, result.PID)
	assert.True(t, result.StateVerified)
	assert.Equal(t, 2, result.BlockedCount)

	require.NoError(t, child.Wait())
	child.Process = nil

	_, statErr := os.Stat(statePath)
	assert.True(t, os.IsNotExist(statErr), "Stop should remove the state file")
	assert.False(t, GetStatus(statePath).Running)
}
