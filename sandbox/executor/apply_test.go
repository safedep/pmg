package executor

import (
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
)

func TestApplyRuntimeOverrides_Read(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead: []string{"/existing"},
		},
	}

	applyRuntimeOverrides(policy, []config.SandboxAllowOverride{
		{Type: config.SandboxAllowRead, Value: "/new/path", Raw: "read=/new/path"},
	})

	assert.Contains(t, policy.Filesystem.AllowRead, "/existing")
	assert.Contains(t, policy.Filesystem.AllowRead, "/new/path")
}

func TestApplyRuntimeOverrides_Write(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Filesystem: sandbox.FilesystemPolicy{
			AllowWrite: []string{"/existing"},
		},
	}

	applyRuntimeOverrides(policy, []config.SandboxAllowOverride{
		{Type: config.SandboxAllowWrite, Value: "/new/file", Raw: "write=/new/file"},
	})

	assert.Contains(t, policy.Filesystem.AllowWrite, "/existing")
	assert.Contains(t, policy.Filesystem.AllowWrite, "/new/file")
}

func TestApplyRuntimeOverrides_Exec(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Process: sandbox.ProcessPolicy{
			AllowExec: []string{"/usr/bin/node"},
		},
	}

	applyRuntimeOverrides(policy, []config.SandboxAllowOverride{
		{Type: config.SandboxAllowExec, Value: "/usr/bin/curl", Raw: "exec=/usr/bin/curl"},
	})

	assert.Contains(t, policy.Process.AllowExec, "/usr/bin/node")
	assert.Contains(t, policy.Process.AllowExec, "/usr/bin/curl")
}

func TestApplyRuntimeOverrides_NetConnect(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Network: sandbox.NetworkPolicy{
			AllowOutbound: []string{"registry.npmjs.org:443"},
		},
	}

	applyRuntimeOverrides(policy, []config.SandboxAllowOverride{
		{Type: config.SandboxAllowNetConnect, Value: "example.com:443", Raw: "net-connect=example.com:443"},
	})

	assert.Contains(t, policy.Network.AllowOutbound, "registry.npmjs.org:443")
	assert.Contains(t, policy.Network.AllowOutbound, "example.com:443")
}

func TestApplyRuntimeOverrides_NetBind(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Network: sandbox.NetworkPolicy{
			AllowBind: []string{},
		},
	}

	applyRuntimeOverrides(policy, []config.SandboxAllowOverride{
		{Type: config.SandboxAllowNetBind, Value: "127.0.0.1:3000", Raw: "net-bind=127.0.0.1:3000"},
	})

	assert.Contains(t, policy.Network.AllowBind, "127.0.0.1:3000")
	assert.NotNil(t, policy.AllowNetworkBind)
	assert.True(t, *policy.AllowNetworkBind)
}

func TestApplyRuntimeOverrides_NetBindPreservesExistingTrue(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		AllowNetworkBind: utils.PtrTo(true),
		Network: sandbox.NetworkPolicy{
			AllowBind: []string{"localhost:8080"},
		},
	}

	applyRuntimeOverrides(policy, []config.SandboxAllowOverride{
		{Type: config.SandboxAllowNetBind, Value: "127.0.0.1:3000", Raw: "net-bind=127.0.0.1:3000"},
	})

	assert.Contains(t, policy.Network.AllowBind, "localhost:8080")
	assert.Contains(t, policy.Network.AllowBind, "127.0.0.1:3000")
	assert.True(t, *policy.AllowNetworkBind)
}

func TestApplyRuntimeOverrides_MultipleOverrides(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Filesystem: sandbox.FilesystemPolicy{},
		Process:    sandbox.ProcessPolicy{},
		Network:    sandbox.NetworkPolicy{},
	}

	overrides := []config.SandboxAllowOverride{
		{Type: config.SandboxAllowWrite, Value: "/path/a", Raw: "write=/path/a"},
		{Type: config.SandboxAllowWrite, Value: "/path/b", Raw: "write=/path/b"},
		{Type: config.SandboxAllowExec, Value: "/usr/bin/curl", Raw: "exec=/usr/bin/curl"},
		{Type: config.SandboxAllowNetConnect, Value: "example.com:443", Raw: "net-connect=example.com:443"},
	}

	applyRuntimeOverrides(policy, overrides)

	assert.Len(t, policy.Filesystem.AllowWrite, 2)
	assert.Len(t, policy.Process.AllowExec, 1)
	assert.Len(t, policy.Network.AllowOutbound, 1)
}

func TestApplyRuntimeOverrides_EmptyOverrides(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Filesystem: sandbox.FilesystemPolicy{
			AllowWrite: []string{"/existing"},
		},
	}

	applyRuntimeOverrides(policy, []config.SandboxAllowOverride{})

	// Policy should be unchanged
	assert.Equal(t, []string{"/existing"}, policy.Filesystem.AllowWrite)
}

func TestApplyRuntimeOverrides_DenyListsUnmodified(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Filesystem: sandbox.FilesystemPolicy{
			DenyWrite: []string{"/protected"},
		},
		Process: sandbox.ProcessPolicy{
			DenyExec: []string{"/usr/bin/curl"},
		},
		Network: sandbox.NetworkPolicy{
			DenyOutbound: []string{"*:*"},
		},
	}

	overrides := []config.SandboxAllowOverride{
		{Type: config.SandboxAllowWrite, Value: "/something", Raw: "write=/something"},
		{Type: config.SandboxAllowExec, Value: "/usr/bin/wget", Raw: "exec=/usr/bin/wget"},
		{Type: config.SandboxAllowNetConnect, Value: "example.com:443", Raw: "net-connect=example.com:443"},
	}

	applyRuntimeOverrides(policy, overrides)

	// Deny lists should never be modified by overrides
	assert.Equal(t, []string{"/protected"}, policy.Filesystem.DenyWrite)
	assert.Equal(t, []string{"/usr/bin/curl"}, policy.Process.DenyExec)
	assert.Equal(t, []string{"*:*"}, policy.Network.DenyOutbound)
}

