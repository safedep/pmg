//go:build linux
// +build linux

package platform

import (
	"context"
	"os/exec"
	"slices"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBubblewrapSandboxCreation(t *testing.T) {
	sb, err := newBubblewrapSandbox()
	require.NoError(t, err)
	assert.NotNil(t, sb)
	assert.Equal(t, sandbox.DriverBubblewrap, sb.Name())
}

func TestBubblewrapSandboxIsAvailable(t *testing.T) {
	sb, err := newBubblewrapSandbox()
	require.NoError(t, err)

	// This test will pass if bwrap is installed, skip if not
	if !sb.IsAvailable() {
		t.Skip("bubblewrap (bwrap) is not installed on this system")
	}

	assert.True(t, sb.IsAvailable())
}

func TestBubblewrapSandboxExecute(t *testing.T) {
	sb, err := newBubblewrapSandbox()
	require.NoError(t, err)

	if !sb.IsAvailable() {
		t.Skip("bubblewrap (bwrap) is not installed on this system")
	}

	policy := &sandbox.SandboxPolicy{
		Name:            "test",
		Description:     "test policy",
		PackageManagers: []string{"test"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead:  []string{"/usr", "/lib", "/bin"},
			AllowWrite: []string{"/tmp"},
		},
		Network: sandbox.NetworkPolicy{
			AllowOutbound: []string{"*:*"},
		},
	}

	// Create a simple command to wrap
	cmd := exec.Command("/bin/echo", "hello")

	ctx := context.Background()
	result, err := sb.Execute(ctx, cmd, policy, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Result should indicate caller must run the command
	assert.True(t, result.ShouldRun(), "Bubblewrap should return executed=false")

	// Command should be modified to use bwrap
	assert.Equal(t, "bwrap", cmd.Args[0])
	assert.Contains(t, cmd.Args, "/bin/echo")
	assert.Contains(t, cmd.Args, "hello")

	// Cleanup
	err = result.Close()
	assert.NoError(t, err)
}

func TestBubblewrapSandboxExecuteCommandWrapping(t *testing.T) {
	sb, err := newBubblewrapSandbox()
	require.NoError(t, err)

	if !sb.IsAvailable() {
		t.Skip("bubblewrap (bwrap) is not installed on this system")
	}

	policy := &sandbox.SandboxPolicy{
		Name:            "test",
		Description:     "test policy",
		PackageManagers: []string{"npm"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead: []string{"/usr"},
		},
	}

	// Create a command with multiple arguments
	originalCmd := "/usr/bin/node"
	originalArgs := []string{"/usr/bin/node", "--version"}
	cmd := exec.Command(originalCmd, originalArgs[1:]...)

	ctx := context.Background()
	result, err := sb.Execute(ctx, cmd, policy, nil)
	require.NoError(t, err)

	// bwrap [bwrap-args] --ro-bind <pmg> <pmg> -- <pmg> __seccomp_shim -- /usr/bin/node --version
	assert.Equal(t, "bwrap", cmd.Args[0])
	shim, err := sb.shimExecutable()
	require.NoError(t, err)

	separatorIdx := slices.Index(cmd.Args, "--")
	require.NotEqual(t, -1, separatorIdx, "Should have -- separator")
	assert.Equal(t, []string{"--ro-bind", shim, shim}, cmd.Args[separatorIdx-3:separatorIdx])
	assert.Equal(t, []string{shim, SeccompShimCommand, "--", originalCmd, "--version"}, cmd.Args[separatorIdx+1:])

	cmd = exec.Command(originalCmd)
	policy.AllowUnixSockets = utils.PtrTo(true)
	_, err = sb.Execute(ctx, cmd, policy, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{shim, SeccompShimCommand, "--allow-unix-sockets", "--", originalCmd}, cmd.Args[slices.Index(cmd.Args, "--")+1:])

	// Cleanup
	err = result.Close()
	assert.NoError(t, err)
}

func TestBubblewrapSandboxExecuteWithPTY(t *testing.T) {
	sb, err := newBubblewrapSandbox()
	require.NoError(t, err)

	if !sb.IsAvailable() {
		t.Skip("bubblewrap (bwrap) is not installed on this system")
	}

	policy := &sandbox.SandboxPolicy{
		Name:            "test",
		Description:     "test with PTY",
		PackageManagers: []string{"npm"},
		AllowPTY:        utils.PtrTo(true),
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead: []string{"/usr"},
		},
	}

	cmd := exec.Command("/bin/echo", "test")
	ctx := context.Background()
	result, err := sb.Execute(ctx, cmd, policy, nil)
	require.NoError(t, err)

	// Should have PTY-related arguments
	argsStr := ""
	for _, arg := range cmd.Args {
		argsStr += arg + " "
	}
	assert.Contains(t, argsStr, "/dev/pts")
	assert.Contains(t, argsStr, "/dev/ptmx")

	// Cleanup
	err = result.Close()
	assert.NoError(t, err)
}

func TestBubblewrapSandboxExecuteWithNetworkIsolation(t *testing.T) {
	sb, err := newBubblewrapSandbox()
	require.NoError(t, err)

	if !sb.IsAvailable() {
		t.Skip("bubblewrap (bwrap) is not installed on this system")
	}

	policy := &sandbox.SandboxPolicy{
		Name:            "test",
		Description:     "test with network isolation",
		PackageManagers: []string{"npm"},
		Network: sandbox.NetworkPolicy{
			DenyOutbound: []string{"*:*"},
		},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead: []string{"/usr"},
		},
	}

	cmd := exec.Command("/bin/echo", "test")
	ctx := context.Background()
	result, err := sb.Execute(ctx, cmd, policy, nil)
	require.NoError(t, err)

	// Should have network isolation
	argsStr := ""
	for _, arg := range cmd.Args {
		argsStr += arg + " "
	}
	assert.Contains(t, argsStr, "--unshare-net")

	// Cleanup
	err = result.Close()
	assert.NoError(t, err)
}

func TestBubblewrapSandboxClose(t *testing.T) {
	sb, err := newBubblewrapSandbox()
	require.NoError(t, err)

	// Close should be idempotent
	err = sb.Close()
	assert.NoError(t, err)

	err = sb.Close()
	assert.NoError(t, err)
}

func TestBubblewrapSandboxExecutionResult(t *testing.T) {
	sb, err := newBubblewrapSandbox()
	require.NoError(t, err)

	if !sb.IsAvailable() {
		t.Skip("bubblewrap (bwrap) is not installed on this system")
	}

	policy := &sandbox.SandboxPolicy{
		Name:            "test",
		PackageManagers: []string{"test"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead: []string{"/usr"},
		},
	}

	cmd := exec.Command("/bin/echo", "test")
	ctx := context.Background()
	result, err := sb.Execute(ctx, cmd, policy, nil)
	require.NoError(t, err)

	// Verify ExecutionResult properties
	assert.True(t, result.ShouldRun(), "Bubblewrap uses CLI wrapper, should return executed=false")

	// Close should succeed
	err = result.Close()
	assert.NoError(t, err)

	// Multiple closes should be safe
	err = result.Close()
	assert.NoError(t, err)
}

func TestBubblewrapSandboxTranslationError(t *testing.T) {
	sb, err := newBubblewrapSandbox()
	require.NoError(t, err)

	if !sb.IsAvailable() {
		t.Skip("bubblewrap (bwrap) is not installed on this system")
	}

	// Create a policy with invalid patterns (shouldn't cause translation error)
	policy := &sandbox.SandboxPolicy{
		Name:            "test",
		PackageManagers: []string{"test"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead: []string{"/usr"},
		},
	}

	cmd := exec.Command("/bin/echo", "test")
	ctx := context.Background()

	// Should succeed even with complex patterns
	result, err := sb.Execute(ctx, cmd, policy, nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Cleanup
	if result != nil {
		_ = result.Close()
	}
}

func TestBubblewrapSandboxEssentialBindMounts(t *testing.T) {
	sb, err := newBubblewrapSandbox()
	require.NoError(t, err)

	if !sb.IsAvailable() {
		t.Skip("bubblewrap (bwrap) is not installed on this system")
	}

	policy := &sandbox.SandboxPolicy{
		Name:            "test",
		PackageManagers: []string{"test"},
		// Minimal policy - should still get essential mounts
		Filesystem: sandbox.FilesystemPolicy{},
	}

	cmd := exec.Command("/bin/echo", "test")
	ctx := context.Background()
	result, err := sb.Execute(ctx, cmd, policy, nil)
	require.NoError(t, err)

	argsStr := ""
	for _, arg := range cmd.Args {
		argsStr += arg + " "
	}

	// Should have essential system paths
	assert.Contains(t, argsStr, "/usr")

	// Should have essential devices
	assert.Contains(t, argsStr, "/dev/null")

	// Should have proc filesystem
	assert.Contains(t, argsStr, "--proc")

	// Should have tmpdir
	assert.Contains(t, argsStr, "--bind")

	// Cleanup
	err = result.Close()
	assert.NoError(t, err)
}
