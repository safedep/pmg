//go:build linux

package platform

import (
	"context"
	"encoding/json"
	"os"
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

	// Close with no resources should return nil
	err := sb.Close()
	assert.NoError(t, err)

	// Close should be idempotent
	err = sb.Close()
	assert.NoError(t, err)
}

func TestLandlockSandbox_Close_CleansUpResources(t *testing.T) {
	sb := &landlockSandbox{abi: newLandlockABI(4)}

	policy := &sandbox.SandboxPolicy{
		Name:            "test",
		Description:     "test policy",
		PackageManagers: []string{"npm"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead: []string{"/usr"},
		},
	}

	cmd := exec.Command("/bin/echo", "hello")
	ctx := context.Background()
	result, err := sb.Execute(ctx, cmd, policy)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify resources exist before Close
	assert.NotEmpty(t, sb.policyFile)
	assert.NotEmpty(t, sb.socketPath)
	assert.NotNil(t, sb.listener)

	_, err = os.Stat(sb.policyFile)
	assert.NoError(t, err, "policy file should exist before Close")
	_, err = os.Stat(sb.socketPath)
	assert.NoError(t, err, "socket file should exist before Close")

	// Close should clean up
	err = result.Close()
	assert.NoError(t, err)

	assert.Empty(t, sb.policyFile)
	assert.Empty(t, sb.socketPath)
	assert.Nil(t, sb.listener)
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

	// cmd.Args should contain --policy-file and --audit-socket
	var policyFileArg, auditSocketArg string
	separatorIdx := -1
	for i, arg := range cmd.Args {
		if arg == "--policy-file" && i+1 < len(cmd.Args) {
			policyFileArg = cmd.Args[i+1]
		}
		if arg == "--audit-socket" && i+1 < len(cmd.Args) {
			auditSocketArg = cmd.Args[i+1]
		}
		if arg == "--" {
			separatorIdx = i
			break
		}
	}
	assert.NotEmpty(t, policyFileArg, "Should have --policy-file arg")
	assert.NotEmpty(t, auditSocketArg, "Should have --audit-socket arg")

	// Policy file should exist on disk
	_, err = os.Stat(policyFileArg)
	assert.NoError(t, err, "Policy temp file should exist")

	// Socket path should exist on disk
	_, err = os.Stat(auditSocketArg)
	assert.NoError(t, err, "Audit socket file should exist")

	// After separator should be the original command and args
	assert.True(t, separatorIdx >= 0, "Should have -- separator in args")
	if separatorIdx >= 0 && separatorIdx+1 < len(cmd.Args) {
		afterSeparator := cmd.Args[separatorIdx+1:]
		assert.Equal(t, "/bin/echo", afterSeparator[0])
		assert.Equal(t, "hello", afterSeparator[1])
		assert.Equal(t, "world", afterSeparator[2])
	}

	// ExtraFiles should be empty (no longer using pipe-based communication)
	assert.Empty(t, cmd.ExtraFiles)

	// result.ShouldRun() should return true (CLI-wrapper pattern, executed=false)
	assert.True(t, result.ShouldRun())

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

	// Policy file path should be stored on the sandbox struct
	require.NotEmpty(t, sb.policyFile)

	// Read and decode the policy from the temp file
	policyData, err := os.ReadFile(sb.policyFile)
	require.NoError(t, err)

	var execPolicy landlockExecPolicy
	err = json.Unmarshal(policyData, &execPolicy)
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

	err = result.Close()
	assert.NoError(t, err)
}
