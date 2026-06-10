package executor

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestApplyRuntimeOverrides_Env(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Environment: sandbox.EnvironmentPolicy{
			Allow: []string{"NPM_TOKEN"},
		},
	}

	applyRuntimeOverrides(policy, []config.SandboxAllowOverride{
		{Type: config.SandboxAllowEnv, Value: "AWS_PROFILE", Raw: "env=AWS_PROFILE"},
	})

	assert.Contains(t, policy.Environment.Allow, "NPM_TOKEN")
	assert.Contains(t, policy.Environment.Allow, "AWS_PROFILE")
}

func TestScrubEnv_RemovesDeniedKeepsAllowed(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Name: "test",
		Environment: sandbox.EnvironmentPolicy{
			Allow: []string{"NPM_TOKEN"},
		},
	}

	cmd := &exec.Cmd{Env: []string{
		"PATH=/usr/bin",
		"NPM_TOKEN=keep-me",
		"AWS_SECRET_ACCESS_KEY=scrub-me",
		"GITHUB_TOKEN=scrub-me-too",
	}}

	scrubbed := scrubEnv(cmd, policy)

	assert.Equal(t, 2, scrubbed)
	assert.Contains(t, cmd.Env, "PATH=/usr/bin")
	assert.Contains(t, cmd.Env, "NPM_TOKEN=keep-me")
	assert.NotContains(t, cmd.Env, "AWS_SECRET_ACCESS_KEY=scrub-me")
	assert.NotContains(t, cmd.Env, "GITHUB_TOKEN=scrub-me-too")
}

func TestScrubEnv_AllowOverrideUnscrubs(t *testing.T) {
	policy := &sandbox.SandboxPolicy{Name: "test"}

	// Simulate a --sandbox-allow env=AWS_SESSION_TOKEN override having been merged.
	applyRuntimeOverrides(policy, []config.SandboxAllowOverride{
		{Type: config.SandboxAllowEnv, Value: "AWS_SESSION_TOKEN", Raw: "env=AWS_SESSION_TOKEN"},
	})

	cmd := &exec.Cmd{Env: []string{"AWS_SESSION_TOKEN=kept"}}
	scrubbed := scrubEnv(cmd, policy)

	assert.Equal(t, 0, scrubbed)
	assert.Contains(t, cmd.Env, "AWS_SESSION_TOKEN=kept")
}

func TestScrubEnv_NilEnvPopulatedThenScrubbed(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "should-be-scrubbed")
	t.Setenv("PMG_ENV_SCRUB_MARKER", "kept")

	policy := &sandbox.SandboxPolicy{Name: "test"}
	cmd := &exec.Cmd{Env: nil}

	scrubEnv(cmd, policy)

	require.NotNil(t, cmd.Env)
	assert.Contains(t, cmd.Env, "PMG_ENV_SCRUB_MARKER=kept")
	assert.NotContains(t, cmd.Env, "GITHUB_TOKEN=should-be-scrubbed")
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

func TestApplyRuntimeOverrides_DenyListsUnmodifiedWhenNoConflict(t *testing.T) {
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

	// Deny lists should be unchanged when overrides don't conflict
	assert.Equal(t, []string{"/protected"}, policy.Filesystem.DenyWrite)
	assert.Equal(t, []string{"/usr/bin/curl"}, policy.Process.DenyExec)
	assert.Equal(t, []string{"*:*"}, policy.Network.DenyOutbound)
}

func TestApplyRuntimeOverrides_RemovesExactDenyConflict(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Filesystem: sandbox.FilesystemPolicy{
			DenyRead:  []string{"/secret", "/other"},
			DenyWrite: []string{"/protected", "/tmp/data"},
		},
		Process: sandbox.ProcessPolicy{
			DenyExec: []string{"/usr/bin/curl", "/bin/bash"},
		},
	}

	overrides := []config.SandboxAllowOverride{
		{Type: config.SandboxAllowRead, Value: "/secret", Raw: "read=/secret"},
		{Type: config.SandboxAllowWrite, Value: "/protected", Raw: "write=/protected"},
		{Type: config.SandboxAllowExec, Value: "/bin/bash", Raw: "exec=/bin/bash"},
	}

	applyRuntimeOverrides(policy, overrides)

	// Exact matches should be removed from deny lists
	assert.Equal(t, []string{"/other"}, policy.Filesystem.DenyRead)
	assert.Equal(t, []string{"/tmp/data"}, policy.Filesystem.DenyWrite)
	assert.Equal(t, []string{"/usr/bin/curl"}, policy.Process.DenyExec)

	// Allow lists should have the overrides
	assert.Contains(t, policy.Filesystem.AllowRead, "/secret")
	assert.Contains(t, policy.Filesystem.AllowWrite, "/protected")
	assert.Contains(t, policy.Process.AllowExec, "/bin/bash")
}

func TestApplyRuntimeOverrides_PreservesGlobDenyPatterns(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Filesystem: sandbox.FilesystemPolicy{
			DenyRead:  []string{"/etc/**"},
			DenyWrite: []string{"/usr/**"},
		},
		Process: sandbox.ProcessPolicy{
			DenyExec: []string{"/usr/bin/*"},
		},
	}

	overrides := []config.SandboxAllowOverride{
		{Type: config.SandboxAllowRead, Value: "/etc/hosts", Raw: "read=/etc/hosts"},
		{Type: config.SandboxAllowWrite, Value: "/usr/local/bin/tool", Raw: "write=/usr/local/bin/tool"},
		{Type: config.SandboxAllowExec, Value: "/usr/bin/git", Raw: "exec=/usr/bin/git"},
	}

	applyRuntimeOverrides(policy, overrides)

	// Glob/wildcard deny patterns must NOT be removed — only exact matches are removed
	assert.Equal(t, []string{"/etc/**"}, policy.Filesystem.DenyRead)
	assert.Equal(t, []string{"/usr/**"}, policy.Filesystem.DenyWrite)
	assert.Equal(t, []string{"/usr/bin/*"}, policy.Process.DenyExec)
}

func TestApplyRuntimeOverrides_VariableDenyNotRemovedByAbsoluteOverride(t *testing.T) {
	// Known limitation: deny entries using ${CWD} or ${HOME} variables are NOT
	// removed by overrides that resolve to absolute paths. removeExactMatch uses
	// literal string comparison, so "${CWD}/blocked.txt" != "/actual/cwd/blocked.txt".
	// The override still adds the path to the allow list, but the unexpanded deny
	// entry remains and will take precedence once the translator expands it.
	cwd, err := os.Getwd()
	assert.NoError(t, err)

	absolutePath := filepath.Join(cwd, "blocked.txt")

	policy := &sandbox.SandboxPolicy{
		Filesystem: sandbox.FilesystemPolicy{
			DenyWrite: []string{"${CWD}/blocked.txt"},
		},
	}

	applyRuntimeOverrides(policy, []config.SandboxAllowOverride{
		{Type: config.SandboxAllowWrite, Value: absolutePath, Raw: "write=./blocked.txt"},
	})

	// The override is added to the allow list
	assert.Contains(t, policy.Filesystem.AllowWrite, absolutePath)

	// But the ${CWD} deny entry is NOT removed because the strings don't match literally.
	// This means the deny rule will still shadow the allow after variable expansion.
	assert.Equal(t, []string{"${CWD}/blocked.txt"}, policy.Filesystem.DenyWrite)
}

func TestApplyProjectOverlayAppendsEntries(t *testing.T) {
	dir := t.TempDir()
	repo := "/repo/example"
	_, err := sandbox.SaveOverlay(dir, repo, &sandbox.Overlay{
		Allow: []sandbox.OverlayAllow{
			{Type: config.SandboxAllowWrite, Value: "/repo/example/.astro"},
			{Type: config.SandboxAllowNetBind, Value: "localhost:4321"},
		},
	})
	require.NoError(t, err)

	policy := &sandbox.SandboxPolicy{Name: "test"}
	applied, err := applyProjectOverlay(policy, dir, repo, false)
	assert.NoError(t, err)
	assert.Equal(t, 2, applied)
	assert.Contains(t, policy.Filesystem.AllowWrite, "/repo/example/.astro")
	assert.Contains(t, policy.Network.AllowBind, "localhost:4321")
	if assert.NotNil(t, policy.AllowNetworkBind) {
		assert.True(t, *policy.AllowNetworkBind)
	}
}

func TestApplyProjectOverlaySkippedWhenLocked(t *testing.T) {
	dir := t.TempDir()
	repo := "/repo/example"
	_, err := sandbox.SaveOverlay(dir, repo, &sandbox.Overlay{
		Allow: []sandbox.OverlayAllow{{Type: config.SandboxAllowWrite, Value: "/repo/example/.astro"}},
	})
	require.NoError(t, err)

	policy := &sandbox.SandboxPolicy{Name: "test"}
	applied, err := applyProjectOverlay(policy, dir, repo, true)
	assert.NoError(t, err)
	assert.Equal(t, 0, applied)
	assert.Empty(t, policy.Filesystem.AllowWrite)
}

func TestApplyProjectOverlayMissingFileIsNoop(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-such")
	policy := &sandbox.SandboxPolicy{Name: "test"}
	applied, err := applyProjectOverlay(policy, dir, "/repo/example", false)
	assert.NoError(t, err)
	assert.Equal(t, 0, applied)
	_, statErr := os.Stat(dir)
	assert.True(t, os.IsNotExist(statErr))
}

func TestApplyProjectOverlayEmptyArgsNoop(t *testing.T) {
	policy := &sandbox.SandboxPolicy{Name: "test"}
	applied, err := applyProjectOverlay(policy, "", "", false)
	assert.NoError(t, err)
	assert.Equal(t, 0, applied)
}
