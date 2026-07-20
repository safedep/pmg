package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writePresetFile(t *testing.T, dir, fileName, content string) string {
	t.Helper()
	path := filepath.Join(dir, fileName)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestPresetRegistryBuiltins(t *testing.T) {
	registry, err := NewPresetRegistry()
	require.NoError(t, err)

	t.Run("official presets load and validate", func(t *testing.T) {
		infos, err := registry.List()
		require.NoError(t, err)

		names := make([]string, 0, len(infos))
		for _, info := range infos {
			names = append(names, info.Preset.Name)
			assert.Equal(t, PresetSourceBuiltin, info.Source)
			assert.NotEmpty(t, info.Raw, "raw YAML preserved for show")
			assert.NoError(t, info.Preset.Validate())
		}

		assert.Contains(t, names, "git")
		assert.Contains(t, names, "astro")
		assert.Contains(t, names, "vite")
		assert.Contains(t, names, "nextjs")
	})

	t.Run("get by name", func(t *testing.T) {
		info, err := registry.Get("git")
		require.NoError(t, err)
		assert.Equal(t, "git", info.Preset.Name)
		assert.Contains(t, info.Preset.Filesystem.AllowRead, "${CWD}/.git/config")
	})

	t.Run("unknown preset is ErrPresetNotFound", func(t *testing.T) {
		_, err := registry.Get("does-not-exist")
		require.ErrorIs(t, err, ErrPresetNotFound)
	})
}

func TestPresetRegistryUserDir(t *testing.T) {
	dir := t.TempDir()
	writePresetFile(t, dir, "myapp.yml", `
kind: preset
name: myapp
description: Custom app preset
metadata:
  author: Community
  labels: [myapp]
filesystem:
  allow_write:
    - ${CWD}/.myapp/**
`)
	writePresetFile(t, dir, "git.yml", `
kind: preset
name: git
description: Attempted builtin override
filesystem:
  allow_write:
    - ${CWD}/anything/**
`)
	writePresetFile(t, dir, "broken.yml", `
kind: preset
name: broken
filesystem:
  deny_read: ["${CWD}/x"]
`)

	registry, err := NewPresetRegistry(WithUserPresetDir(dir))
	require.NoError(t, err)

	t.Run("user preset resolves", func(t *testing.T) {
		info, err := registry.Get("myapp")
		require.NoError(t, err)
		assert.Equal(t, PresetSourceUser, info.Source)
		assert.Equal(t, filepath.Join(dir, "myapp.yml"), info.Path)
	})

	t.Run("builtin wins name collisions", func(t *testing.T) {
		info, err := registry.Get("git")
		require.NoError(t, err)
		assert.Equal(t, PresetSourceBuiltin, info.Source)
		assert.Contains(t, info.Preset.Filesystem.AllowRead, "${CWD}/.git/config")
	})

	t.Run("list marks shadowed user presets and skips invalid files", func(t *testing.T) {
		infos, err := registry.List()
		require.NoError(t, err)

		var shadowedGit, sawBroken bool
		for _, info := range infos {
			if info.Preset.Name == "git" && info.Source == PresetSourceUser {
				shadowedGit = info.Shadowed
			}
			if info.Preset.Name == "broken" {
				sawBroken = true
			}
		}
		assert.True(t, shadowedGit)
		assert.False(t, sawBroken, "invalid preset files are skipped")
	})

	t.Run("missing user dir is a clean no-op", func(t *testing.T) {
		registry, err := NewPresetRegistry(WithUserPresetDir(filepath.Join(dir, "missing")))
		require.NoError(t, err)

		_, err = registry.Get("git")
		assert.NoError(t, err)
	})
}

func TestProfilePresetsExpansion(t *testing.T) {
	t.Run("custom profile with presets gets allowances", func(t *testing.T) {
		dir := t.TempDir()
		path := writePresetFile(t, dir, "pnpm-custom.yml", `
name: pnpm-custom
description: Custom pnpm profile with presets
inherits: pnpm
package_managers: [pnpm]
presets: [git, astro]
`)

		registry, err := NewProfileRegistry()
		require.NoError(t, err)

		policy, err := registry.LoadCustomProfile(path)
		require.NoError(t, err)

		assert.Contains(t, policy.Filesystem.AllowRead, "${CWD}/.git/config")
		assert.Contains(t, policy.Filesystem.AllowWrite, "${CWD}/.git/**")
		assert.Contains(t, policy.Filesystem.AllowWrite, "${CWD}/.astro/**")
		assert.Contains(t, policy.Network.AllowBind, "localhost:4321")
		assert.Equal(t, []string{"git", "astro"}, policy.Presets, "names kept for provenance")

		// Inherited base profile rules are still present
		assert.Contains(t, policy.Filesystem.AllowWrite, "${CWD}/node_modules/**")
	})

	t.Run("unknown preset in profile is a hard error", func(t *testing.T) {
		dir := t.TempDir()
		path := writePresetFile(t, dir, "bad.yml", `
name: bad
package_managers: [pnpm]
presets: [does-not-exist]
filesystem:
  allow_read: ["${CWD}/**"]
`)

		registry, err := NewProfileRegistry()
		require.NoError(t, err)

		_, err = registry.LoadCustomProfile(path)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPresetNotFound)
	})

	t.Run("profile authored deny survives a preset allowing the same path", func(t *testing.T) {
		dir := t.TempDir()
		path := writePresetFile(t, dir, "deny-wins.yml", `
name: deny-wins
package_managers: [pnpm]
presets: [git]
filesystem:
  deny_read: ["${CWD}/.git/config"]
`)

		registry, err := NewProfileRegistry()
		require.NoError(t, err)

		policy, err := registry.LoadCustomProfile(path)
		require.NoError(t, err)

		assert.Contains(t, policy.Filesystem.AllowRead, "${CWD}/.git/config")
		assert.Contains(t, policy.Filesystem.DenyRead, "${CWD}/.git/config",
			"presets are additive-only, they never remove authored deny rules")
	})

	t.Run("profile with only presets passes resolved validation", func(t *testing.T) {
		dir := t.TempDir()
		path := writePresetFile(t, dir, "presets-only.yml", `
name: presets-only
package_managers: [pnpm]
presets: [git]
`)

		registry, err := NewProfileRegistry()
		require.NoError(t, err)

		policy, err := registry.LoadCustomProfile(path)
		require.NoError(t, err)
		assert.Contains(t, policy.Filesystem.AllowWrite, "${CWD}/.git/**")
	})
}
