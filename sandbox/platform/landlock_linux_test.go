//go:build linux

package platform

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLandlockSandbox_Name(t *testing.T) {
	sb := &landlockSandbox{abi: newLandlockABI(4)}
	assert.Equal(t, "landlock", sb.Name())
}

func TestLandlockSandbox_IsAvailable_True(t *testing.T) {
	sb := &landlockSandbox{abi: newLandlockABI(4)}
	assert.True(t, sb.IsAvailable())

	sb2 := &landlockSandbox{abi: newLandlockABI(1)}
	assert.True(t, sb2.IsAvailable())
}

func TestLandlockSandbox_IsAvailable_False(t *testing.T) {
	// nil ABI
	sb := &landlockSandbox{abi: nil}
	assert.False(t, sb.IsAvailable())

	// Version 0
	sb2 := &landlockSandbox{abi: newLandlockABI(0)}
	assert.False(t, sb2.IsAvailable())
}

func TestLandlockSandbox_Close(t *testing.T) {
	sb := &landlockSandbox{abi: newLandlockABI(4)}

	// Close should return nil
	err := sb.Close()
	assert.NoError(t, err)

	// Close should be idempotent
	err = sb.Close()
	assert.NoError(t, err)
}

func TestLandlockSandbox_Execute_RewiresCmd(t *testing.T) {
	sb := &landlockSandbox{abi: newLandlockABI(4)}

	policy := &sandbox.SandboxPolicy{
		Name:            "test",
		Description:     "test policy",
		PackageManagers: []string{"npm"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead: []string{"/usr"},
		},
	}

	cmd := exec.Command("/bin/echo", "hello", "world")

	ctx := context.Background()
	result, err := sb.Execute(ctx, cmd, policy)
	require.NoError(t, err)
	require.NotNil(t, result)

	// cmd.Path should be the current executable (self re-exec)
	assert.NotEmpty(t, cmd.Path)

	// cmd.Args should contain __landlock_sandbox_exec
	assert.Equal(t, "__landlock_sandbox_exec", cmd.Args[1])

	// cmd.Args should contain "--" separator
	separatorFound := false
	separatorIdx := -1
	for i, arg := range cmd.Args {
		if arg == "--" {
			separatorFound = true
			separatorIdx = i
			break
		}
	}
	assert.True(t, separatorFound, "Should have -- separator in args")

	// After separator should be the original command and args
	if separatorIdx >= 0 && separatorIdx+1 < len(cmd.Args) {
		afterSeparator := cmd.Args[separatorIdx+1:]
		assert.Equal(t, "/bin/echo", afterSeparator[0])
		assert.Equal(t, "hello", afterSeparator[1])
		assert.Equal(t, "world", afterSeparator[2])
	}

	// ExtraFiles should have exactly 2 entries (policyR at FD=3, auditW at FD=4)
	assert.Len(t, cmd.ExtraFiles, 2)

	// result.ShouldRun() should return true (CLI-wrapper pattern, executed=false)
	assert.True(t, result.ShouldRun())

	// Cleanup: close the extra files to avoid leaking
	for _, f := range cmd.ExtraFiles {
		if f != nil {
			f.Close()
		}
	}

	err = result.Close()
	assert.NoError(t, err)
}

func TestLandlockSandbox_Execute_PolicySerialized(t *testing.T) {
	sb := &landlockSandbox{abi: newLandlockABI(4)}

	policy := &sandbox.SandboxPolicy{
		Name:            "test",
		Description:     "test policy for serialization",
		PackageManagers: []string{"npm"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead:  []string{"/usr", "/lib"},
			AllowWrite: []string{"/tmp/test"},
		},
		Process: sandbox.ProcessPolicy{
			AllowExec: []string{"/usr/bin/node"},
		},
	}

	cmd := exec.Command("/bin/echo", "test")

	ctx := context.Background()
	result, err := sb.Execute(ctx, cmd, policy)
	require.NoError(t, err)
	require.NotNil(t, result)

	// ExtraFiles[0] is the policy read end (FD=3 in child)
	require.Len(t, cmd.ExtraFiles, 2)
	policyR := cmd.ExtraFiles[0]
	require.NotNil(t, policyR)

	// Read and decode the policy from the pipe
	var execPolicy landlockExecPolicy
	decoder := json.NewDecoder(policyR)
	err = decoder.Decode(&execPolicy)
	require.NoError(t, err)

	// Verify the exec policy contains the command info
	assert.Equal(t, "/bin/echo", execPolicy.Command)
	assert.Equal(t, []string{"test"}, execPolicy.Args)

	// Verify filesystem rules were translated (at least our AllowRead paths + implicit rules)
	assert.NotEmpty(t, execPolicy.FilesystemRules)

	// Check that /usr is in the filesystem rules
	foundUsr := false
	for _, rule := range execPolicy.FilesystemRules {
		if rule.Path == "/usr" {
			foundUsr = true
			break
		}
	}
	assert.True(t, foundUsr, "Should have /usr in filesystem rules")

	// Cleanup
	policyR.Close()
	if cmd.ExtraFiles[1] != nil {
		cmd.ExtraFiles[1].Close()
	}

	err = result.Close()
	assert.NoError(t, err)
}
