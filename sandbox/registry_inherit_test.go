package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeProfileYAML(t *testing.T, path, yamlText string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(yamlText), 0o644))
	return path
}

func TestBuiltinLineage(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	base, err := registry.GetProfile("npm-restrictive")
	require.NoError(t, err)
	assert.Equal(t, []string{"npm-restrictive"}, base.Lineage)
	assert.Empty(t, base.Parent())

	npx, err := registry.GetProfile("npx")
	require.NoError(t, err)
	assert.Equal(t, []string{"npm-restrictive", "npx"}, npx.Lineage)
	assert.Equal(t, "npm-restrictive", npx.Parent())

	summaries, err := registry.ListProfiles()
	require.NoError(t, err)
	for _, s := range summaries {
		if s.Name == "npx" {
			assert.Equal(t, "npm-restrictive", s.Inherits)
		}
	}
}

func TestLoadCustomProfileChainThroughFiles(t *testing.T) {
	dir := t.TempDir()
	basePath := writeProfileYAML(t, filepath.Join(dir, "base.yml"), `
name: base
description: base
inherits: npm-restrictive
package_managers: [npm]
filesystem:
  allow_read:
    - /base/**
allow_pty: true
`)
	leafPath := writeProfileYAML(t, filepath.Join(dir, "nested", "leaf.yml"), `
name: leaf
description: leaf
inherits: ../base.yml
package_managers: [npm]
filesystem:
  allow_read:
    - /leaf/**
network:
  allow_outbound:
    - leaf.example.com:443
`)

	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	leaf, err := registry.LoadCustomProfile(leafPath)
	require.NoError(t, err)

	assert.Empty(t, leaf.Inherits)
	assert.Equal(t, []string{"npm-restrictive", filepath.Join(dir, "nested", "../base.yml"), leafPath}, leaf.Lineage)
	assert.Contains(t, leaf.Filesystem.AllowRead, "/usr/**", "rule from the built-in base")
	assert.Contains(t, leaf.Filesystem.AllowRead, "/base/**", "rule from the middle profile")
	assert.Contains(t, leaf.Filesystem.AllowRead, "/leaf/**", "rule from the leaf")
	assert.Contains(t, leaf.Network.AllowOutbound, "registry.npmjs.org:443")
	assert.Contains(t, leaf.Network.AllowOutbound, "leaf.example.com:443")
	assert.True(t, *leaf.AllowPTY, "boolean set by the middle profile reaches the leaf")

	base, err := registry.LoadCustomProfile(basePath)
	require.NoError(t, err)
	assert.Equal(t, []string{"npm-restrictive", basePath}, base.Lineage)
}

func TestLoadCustomProfileInheritsUserProfileByName(t *testing.T) {
	userDir := t.TempDir()
	writeProfileYAML(t, filepath.Join(userDir, "corp.yml"), `
name: corp
description: corp base
inherits: pypi-restrictive
package_managers: [pip]
filesystem:
  allow_read:
    - /corp/**
`)
	leafPath := writeProfileYAML(t, filepath.Join(t.TempDir(), "ci.yml"), `
name: ci
description: ci
inherits: corp
package_managers: [pip]
network:
  deny_outbound:
    - "*:*"
`)

	registry, err := newDefaultProfileRegistry(WithUserProfileDir(userDir))
	require.NoError(t, err)

	leaf, err := registry.LoadCustomProfile(leafPath)
	require.NoError(t, err)

	assert.Equal(t, []string{"pypi-restrictive", filepath.Join(userDir, "corp.yml"), leafPath}, leaf.Lineage)
	assert.Contains(t, leaf.Filesystem.AllowRead, "/corp/**")
	assert.Contains(t, leaf.Network.AllowOutbound, "pypi.org:443")
}

func TestLoadCustomProfileInheritsTemplateByName(t *testing.T) {
	templatePath := writeProfileYAML(t, filepath.Join(t.TempDir(), "runner.yml"), `
name: runner
description: runner template
inherits: npm-restrictive
package_managers: [npm]
network:
  deny_outbound:
    - "*:*"
`)
	leafPath := writeProfileYAML(t, filepath.Join(t.TempDir(), "ci.yml"), `
name: ci
description: ci
inherits: runner
package_managers: [npm]
network:
  allow_outbound:
    - ci.example.com:443
`)

	registry, err := newDefaultProfileRegistry(WithPolicyTemplates(map[string]string{"runner": templatePath}))
	require.NoError(t, err)

	leaf, err := registry.LoadCustomProfile(leafPath)
	require.NoError(t, err)

	assert.Equal(t, []string{"npm-restrictive", templatePath, leafPath}, leaf.Lineage)
	assert.Contains(t, leaf.Network.AllowOutbound, "ci.example.com:443")
	assert.Contains(t, leaf.Network.DenyOutbound, "*:*")
}

func TestLoadCustomProfileCycleIsAnError(t *testing.T) {
	dir := t.TempDir()
	aPath := writeProfileYAML(t, filepath.Join(dir, "a.yml"), `
name: a
description: a
inherits: b.yml
package_managers: [npm]
filesystem:
  allow_read:
    - /a/**
`)
	writeProfileYAML(t, filepath.Join(dir, "b.yml"), `
name: b
description: b
inherits: a.yml
package_managers: [npm]
filesystem:
  allow_read:
    - /b/**
`)
	selfPath := writeProfileYAML(t, filepath.Join(dir, "self.yml"), `
name: self
description: self
inherits: self.yml
package_managers: [npm]
filesystem:
  allow_read:
    - /self/**
`)

	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	_, err = registry.LoadCustomProfile(aPath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileInvalid)
	assert.Contains(t, err.Error(), "inheritance cycle")

	_, err = registry.LoadCustomProfile(selfPath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileInvalid)
	assert.Contains(t, err.Error(), "inheritance cycle")
}

func TestLoadCustomProfileUnknownParent(t *testing.T) {
	leafPath := writeProfileYAML(t, filepath.Join(t.TempDir(), "ci.yml"), `
name: ci
description: ci
inherits: no-such-profile
package_managers: [npm]
filesystem:
  allow_read:
    - /ci/**
`)

	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	_, err = registry.LoadCustomProfile(leafPath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)
	assert.Contains(t, err.Error(), "inherits from unknown profile 'no-such-profile'")
}

func TestResolveProfileCopiesLineage(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	resolved, err := registry.ResolveProfile("npx", ResolveOptions{})
	require.NoError(t, err)
	assert.Equal(t, []string{"npm-restrictive", "npx"}, resolved.Lineage)

	resolved.Lineage[0] = "changed"
	cached, err := registry.GetProfile("npx")
	require.NoError(t, err)
	assert.Equal(t, "npm-restrictive", cached.Lineage[0])
}
