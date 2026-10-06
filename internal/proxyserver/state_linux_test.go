//go:build linux

package proxyserver

import (
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The test process is the child's parent and reaps it only in the cleanup, so
// the child stays a zombie in between, as the daemon does under a PID 1 that
// never reaps.
func TestIsRunningZombie(t *testing.T) {
	cmd := exec.Command("true")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { assert.NoError(t, cmd.Wait()) })

	s := State{PID: cmd.Process.Pid}
	assert.Eventually(t, func() bool { return !s.IsRunning() }, 5*time.Second, 10*time.Millisecond)
}
