//go:build linux

package proxyserver

import (
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZombieStat(t *testing.T) {
	tests := []struct {
		name string
		stat string
		want bool
	}{
		{"zombie", "25 (pmg) Z 1 25 25 0 -1", true},
		{"dead", "25 (pmg) X 1 25 25 0 -1", true},
		{"sleeping", "25 (pmg) S 1 25 25 0 -1", false},
		{"running", "25 (pmg) R 1 25 25 0 -1", false},
		{"comm with spaces and parens", "25 (a) Z (b) S 1 25 25", false},
		{"comm with spaces and parens, zombie", "25 (a) S (b) Z 1 25 25", true},
		{"no comm", "garbage", false},
		{"no state", "25 (pmg)", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, zombieStat(tt.stat))
		})
	}
}

// The test process is the child's parent and reaps it only in the cleanup, so
// the child stays a zombie in between, as the daemon does under a PID 1 that
// never reaps.
func TestIsRunningZombie(t *testing.T) {
	cmd := exec.Command("true")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { assert.NoError(t, cmd.Wait()) })

	pid := cmd.Process.Pid
	require.Eventually(t, func() bool { return isZombie(pid) }, 5*time.Second, 10*time.Millisecond)
	assert.False(t, State{PID: pid}.IsRunning())
}

func TestIsRunningLiveChild(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		assert.NoError(t, cmd.Process.Kill())
		assert.Error(t, cmd.Wait())
	})

	assert.True(t, State{PID: cmd.Process.Pid}.IsRunning())
}
