package platform

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The test binary starts itself as a child. The child reports its parent,
// which is this binary, by file name.
func TestParentProcessName(t *testing.T) {
	if os.Getenv("PMG_PARENT_PROCESS_CHILD") == "1" {
		name, err := ParentProcessName()
		require.NoError(t, err)
		// A newline, because the test binary prints PASS after this.
		_, _ = os.Stdout.WriteString(name + "\n")
		return
	}

	self, err := os.Executable()
	require.NoError(t, err)
	child := exec.Command(self, "-test.run=^TestParentProcessName$")
	child.Env = append(os.Environ(), "PMG_PARENT_PROCESS_CHILD=1")
	output, err := child.Output()
	require.NoError(t, err, string(output))

	reported := strings.TrimSpace(strings.Split(string(output), "\n")[0])
	assert.Equal(t, strings.ToLower(filepath.Base(self)), strings.ToLower(reported))
}

func TestIsProcessAliveCurrentProcess(t *testing.T) {
	assert.True(t, IsProcessAlive(os.Getpid()))
}

func TestIsProcessAliveInvalidPID(t *testing.T) {
	tests := []struct {
		name string
		pid  int
	}{
		{name: "zero", pid: 0},
		{name: "negative", pid: -1},
		{name: "large negative", pid: -9999},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, IsProcessAlive(tt.pid))
		})
	}
}

func TestIsProcessAliveChildLifecycle(t *testing.T) {
	if os.Getenv("PMG_ALIVE_CHILD") == "1" {
		_, err := io.ReadAll(os.Stdin)
		require.NoError(t, err)
		return
	}

	self, err := os.Executable()
	require.NoError(t, err)
	child := exec.Command(self, "-test.run=^TestIsProcessAliveChildLifecycle$")
	child.Env = append(os.Environ(), "PMG_ALIVE_CHILD=1")
	stdin, err := child.StdinPipe()
	require.NoError(t, err)

	require.NoError(t, child.Start())
	pid := child.Process.Pid
	var waited bool
	t.Cleanup(func() {
		if err := stdin.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Logf("close child stdin: %v", err)
		}
		if !waited {
			if err := child.Wait(); err != nil {
				t.Logf("wait child: %v", err)
			}
		}
	})

	assert.True(t, IsProcessAlive(pid), "live child process should report alive")

	require.NoError(t, stdin.Close())

	// Even before Wait releases the process handle, GetExitCodeProcess reports
	// the real exit code rather than STILL_ACTIVE.
	require.Eventually(t, func() bool {
		return !IsProcessAlive(pid)
	}, 5*time.Second, 20*time.Millisecond, "exited unwaited child should not report alive")

	require.NoError(t, child.Wait())
	waited = true
	assert.False(t, IsProcessAlive(pid), "waited child process should not report alive")
}
