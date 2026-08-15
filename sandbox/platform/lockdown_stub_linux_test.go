//go:build linux

package platform

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bubblewrap has no network enforcement primitives beyond namespace
// isolation, so it keeps rejecting lockdown rather than running unconfined.
func TestBubblewrapRejectsNetworkViaProxyOnly(t *testing.T) {
	bwrap, err := newBubblewrapSandbox()
	require.NoError(t, err)

	policy := &sandbox.SandboxPolicy{
		Name:                "lockdown",
		PackageManagers:     []string{"npm"},
		Filesystem:          sandbox.FilesystemPolicy{AllowRead: []string{"/tmp"}},
		NetworkViaProxyOnly: utils.PtrTo(true),
	}

	cmd := exec.Command("/bin/true")
	result, err := bwrap.Execute(context.Background(), cmd, policy,
		&sandbox.ExecutionContext{ProxyAddr: "127.0.0.1:54321"})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "not yet supported on this platform")
}

// Lockdown without a runtime proxy is a hard error: never run unconfined.
func TestLandlockLockdownFailsClosedWithoutProxy(t *testing.T) {
	sb := &landlockSandbox{abi: newLandlockABI(4)}

	policy := &sandbox.SandboxPolicy{
		Name:                "lockdown",
		PackageManagers:     []string{"npm"},
		Filesystem:          sandbox.FilesystemPolicy{AllowRead: []string{"/tmp"}},
		NetworkViaProxyOnly: utils.PtrTo(true),
	}

	for _, rt := range []*sandbox.ExecutionContext{nil, {}} {
		cmd := exec.Command("/bin/true")
		result, err := sb.Execute(context.Background(), cmd, policy, rt)

		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "requires the PMG proxy flow")
	}
}

// A non-loopback proxy address would defeat confinement; rejected ahead of
// any sandbox setup.
func TestLandlockLockdownRejectsNonLoopbackProxy(t *testing.T) {
	sb := &landlockSandbox{abi: newLandlockABI(4)}

	policy := &sandbox.SandboxPolicy{
		Name:                "lockdown",
		PackageManagers:     []string{"npm"},
		Filesystem:          sandbox.FilesystemPolicy{AllowRead: []string{"/tmp"}},
		NetworkViaProxyOnly: utils.PtrTo(true),
	}

	cmd := exec.Command("/bin/true")
	result, err := sb.Execute(context.Background(), cmd, policy,
		&sandbox.ExecutionContext{ProxyAddr: "203.0.113.9:8080"})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "refusing non-loopback proxy address")
}

func TestLandlockLockdownAcceptedWithProxy(t *testing.T) {
	sb := &landlockSandbox{abi: newLandlockABI(4)}

	policy := &sandbox.SandboxPolicy{
		Name:                "lockdown",
		PackageManagers:     []string{"npm"},
		Filesystem:          sandbox.FilesystemPolicy{AllowRead: []string{"/tmp"}},
		NetworkViaProxyOnly: utils.PtrTo(true),
		AllowNetworkBind:    utils.PtrTo(true),
	}

	cmd := exec.Command("/bin/true")
	result, err := sb.Execute(context.Background(), cmd, policy,
		&sandbox.ExecutionContext{ProxyAddr: "127.0.0.1:54321"})
	require.NoError(t, err)
	require.NotNil(t, result)

	// The serialized policy carries the confinement config to the supervisor.
	policyData, err := os.ReadFile(sb.policyFile)
	require.NoError(t, err)

	var execPolicy landlockExecPolicy
	require.NoError(t, json.Unmarshal(policyData, &execPolicy))

	assert.True(t, execPolicy.Network.Lockdown)
	assert.Equal(t, uint16(54321), execPolicy.Network.ProxyPort)
	assert.True(t, execPolicy.Network.AllowBind)
	assert.False(t, execPolicy.Network.AllowDirectDNS)

	require.NoError(t, result.Close())
}
