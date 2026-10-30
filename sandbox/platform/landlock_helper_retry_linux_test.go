//go:build linux

package platform

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// A started Cmd cannot start again, so the retry without the PID and IPC
// namespaces must build a new command.
func TestStartShimWithFallback(t *testing.T) {
	t.Run("retries with a new command and without the extra flags", func(t *testing.T) {
		var flags []uintptr
		newCmd := func(cloneflags uintptr) *exec.Cmd {
			flags = append(flags, cloneflags)
			cmd := exec.Command("true")
			cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: cloneflags}
			return cmd
		}
		var fallbackErr error
		// An unprivileged process cannot create a PID namespace without a
		// user namespace, so the first start fails with EPERM, as on a
		// restricted host.
		cmd, err := startShimWithFallback(newCmd, unix.CLONE_NEWPID, unix.CLONE_NEWPID, func(err error) { fallbackErr = err })
		if err == nil && len(flags) == 1 {
			require.NoError(t, cmd.Wait())
			t.Skip("this host lets the test create a PID namespace")
		}
		require.NoError(t, err)
		require.NoError(t, cmd.Wait())
		assert.Equal(t, []uintptr{unix.CLONE_NEWPID, 0}, flags)
		// A host refuses the namespace with EPERM or EINVAL. Both retry.
		assert.True(t, errors.Is(fallbackErr, unix.EPERM) || errors.Is(fallbackErr, unix.EINVAL), "fallback error: %v", fallbackErr)
	})

	t.Run("does not retry another start error", func(t *testing.T) {
		calls := 0
		newCmd := func(cloneflags uintptr) *exec.Cmd {
			calls++
			return exec.Command("/nonexistent/pmg-shim")
		}
		fallbacks := 0
		_, err := startShimWithFallback(newCmd, unix.CLONE_NEWPID, unix.CLONE_NEWPID, func(error) { fallbacks++ })
		require.ErrorContains(t, err, "start shim")
		assert.Equal(t, 1, calls)
		assert.Equal(t, 0, fallbacks)
	})
}
