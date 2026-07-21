package executor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyRuntimeOverridesPreset(t *testing.T) {
	registry, err := sandbox.NewPresetRegistry()
	require.NoError(t, err)

	t.Run("expands preset allowances into the policy", func(t *testing.T) {
		policy := &sandbox.SandboxPolicy{Name: "test"}
		applyRuntimeOverrides(policy, []config.SandboxAllowOverride{
			{Type: config.SandboxAllowPreset, Value: "git", Raw: "preset=git"},
			{Type: config.SandboxAllowPreset, Value: "astro", Raw: "preset=astro"},
		}, registry)

		assert.Contains(t, policy.Filesystem.AllowRead, "${CWD}/.git/config")
		assert.Contains(t, policy.Filesystem.AllowWrite, "${CWD}/.git/**")
		assert.Contains(t, policy.Filesystem.AllowWrite, "${CWD}/.astro/**")
		assert.Contains(t, policy.Network.AllowBind, "localhost:4321")
		assert.True(t, utils.SafelyGetValue(policy.AllowNetworkBind))
	})

	t.Run("unknown preset is a warning, never fatal", func(t *testing.T) {
		policy := &sandbox.SandboxPolicy{Name: "test"}
		applyRuntimeOverrides(policy, []config.SandboxAllowOverride{
			{Type: config.SandboxAllowPreset, Value: "does-not-exist", Raw: "preset=does-not-exist"},
		}, registry)

		assert.Empty(t, policy.Filesystem.AllowRead)
		assert.Empty(t, policy.Filesystem.AllowWrite)
	})

	t.Run("nil registry skips preset entries", func(t *testing.T) {
		policy := &sandbox.SandboxPolicy{Name: "test"}
		applyRuntimeOverrides(policy, []config.SandboxAllowOverride{
			{Type: config.SandboxAllowPreset, Value: "git", Raw: "preset=git"},
		}, nil)

		assert.Empty(t, policy.Filesystem.AllowRead)
	})
}

func TestApplyProjectOverlayWithPresets(t *testing.T) {
	dir := t.TempDir()
	repo := "/repo/example"
	_, err := sandbox.SaveOverlay(dir, repo, &sandbox.Overlay{
		Allow: []sandbox.OverlayAllow{
			{Type: config.SandboxAllowPreset, Value: "git"},
			{Type: config.SandboxAllowWrite, Value: "/repo/example/.astro"},
		},
	})
	require.NoError(t, err)

	registry, err := sandbox.NewPresetRegistry()
	require.NoError(t, err)

	policy := &sandbox.SandboxPolicy{Name: "test"}
	applied, err := applyProjectOverlay(policy, dir, repo, false, registry)
	require.NoError(t, err)

	assert.Equal(t, 2, applied)
	assert.Contains(t, policy.Filesystem.AllowRead, "${CWD}/.git/config")
	assert.Contains(t, policy.Filesystem.AllowWrite, "${CWD}/.git/**")
	assert.Contains(t, policy.Filesystem.AllowWrite, "/repo/example/.astro")
}

func TestPresetExpansionEquivalentAcrossEntryPaths(t *testing.T) {
	presetRegistry, err := sandbox.NewPresetRegistry()
	require.NoError(t, err)

	viaOverride := &sandbox.SandboxPolicy{Name: "test", PackageManagers: []string{"pnpm"}}
	applyRuntimeOverrides(viaOverride, []config.SandboxAllowOverride{
		{Type: config.SandboxAllowPreset, Value: "git", Raw: "preset=git"},
		{Type: config.SandboxAllowPreset, Value: "astro", Raw: "preset=astro"},
	}, presetRegistry)

	dir := t.TempDir()
	profilePath := filepath.Join(dir, "via-profile.yml")
	require.NoError(t, os.WriteFile(profilePath, []byte(`
name: via-profile
package_managers: [pnpm]
presets: [git, astro]
`), 0o600))

	profileRegistry, err := sandbox.NewProfileRegistry()
	require.NoError(t, err)
	viaProfile, err := profileRegistry.LoadCustomProfile(profilePath)
	require.NoError(t, err)

	assert.Equal(t, viaProfile.Filesystem.AllowRead, viaOverride.Filesystem.AllowRead)
	assert.Equal(t, viaProfile.Filesystem.AllowWrite, viaOverride.Filesystem.AllowWrite)
	assert.Equal(t, viaProfile.Network.AllowBind, viaOverride.Network.AllowBind)
	assert.Equal(t, viaProfile.Environment.Allow, viaOverride.Environment.Allow)
	assert.Equal(t,
		utils.SafelyGetValue(viaProfile.AllowNetworkBind),
		utils.SafelyGetValue(viaOverride.AllowNetworkBind))
}
