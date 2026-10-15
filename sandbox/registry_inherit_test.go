package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func registerFakeBuiltin(r *defaultProfileRegistry, name, inherits string) {
	r.profiles[name] = &SandboxPolicy{
		Name:            name,
		Inherits:        inherits,
		PackageManagers: []string{"npm"},
		Filesystem:      FilesystemPolicy{AllowRead: []string{"/" + name + "/**"}},
	}
	r.builtins[name] = struct{}{}
}

func TestBuiltinInheritanceChainOfThree(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	registry.mu.Lock()
	registerFakeBuiltin(registry, "fake-base", "")
	registerFakeBuiltin(registry, "fake-mid", "fake-base")
	registerFakeBuiltin(registry, "fake-leaf", "fake-mid")
	// The leaf resolves first and pulls the chain with it.
	err = registry.resolveBuiltinInheritance("fake-leaf", nil)
	registry.mu.Unlock()
	require.NoError(t, err)

	leaf := registry.profiles["fake-leaf"]
	assert.Equal(t, []string{"fake-base", "fake-mid", "fake-leaf"}, leaf.Lineage)
	assert.ElementsMatch(t, []string{"/fake-base/**", "/fake-mid/**", "/fake-leaf/**"}, leaf.Filesystem.AllowRead)

	mid := registry.profiles["fake-mid"]
	assert.Equal(t, []string{"fake-base", "fake-mid"}, mid.Lineage)
	assert.Empty(t, mid.Inherits)
}

func TestBuiltinInheritanceCycleIsAnError(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	registry.mu.Lock()
	registerFakeBuiltin(registry, "cycle-a", "cycle-b")
	registerFakeBuiltin(registry, "cycle-b", "cycle-a")
	err = registry.resolveBuiltinInheritance("cycle-a", nil)
	registry.mu.Unlock()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileInvalid)
	assert.Contains(t, err.Error(), "inheritance cycle: cycle-a < cycle-b < cycle-a")
}

func TestBuiltinCannotInheritACustomProfile(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	registry.mu.Lock()
	registerFakeBuiltin(registry, "fake-child", "not-a-builtin")
	err = registry.resolveBuiltinInheritance("fake-child", nil)
	registry.mu.Unlock()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileNotFound)
}

func TestTemplateNameResolution(t *testing.T) {
	dir := t.TempDir()
	overridePath := writeProfileYAML(t, filepath.Join(dir, "npm-override.yml"), `
name: npm-restrictive
description: template that overrides the built-in
inherits: npm-restrictive
package_managers: [npm]
network:
  allow_outbound:
    - override.example.com:443
`)
	runnerPath := writeProfileYAML(t, filepath.Join(dir, "runner.yml"), `
name: runner
description: template with its own name
inherits: npm-restrictive
package_managers: [npm]
network:
  allow_outbound:
    - runner.example.com:443
`)
	childPath := writeProfileYAML(t, filepath.Join(dir, "child.yml"), `
name: child
description: inherits the built-in name
inherits: npm-restrictive
package_managers: [npm]
network:
  allow_outbound:
    - child.example.com:443
`)

	registry, err := newDefaultProfileRegistry(WithPolicyTemplates(map[string]string{
		"npm-restrictive": overridePath,
		"runner":          runnerPath,
	}))
	require.NoError(t, err)

	// A template with its own name resolves by that name.
	runner, err := registry.GetProfile("runner")
	require.NoError(t, err)
	assert.Equal(t, []string{"npm-restrictive", runnerPath}, runner.Lineage)

	// The built-in wins over the template that shadows its name, by name
	// and in inherits, so the override template itself can inherit it.
	builtin, err := registry.GetProfile("npm-restrictive")
	require.NoError(t, err)
	assert.Equal(t, []string{"npm-restrictive"}, builtin.Lineage)
	assert.NotContains(t, builtin.Network.AllowOutbound, "override.example.com:443")

	child, err := registry.LoadCustomProfile(childPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"npm-restrictive", childPath}, child.Lineage)
	assert.NotContains(t, child.Network.AllowOutbound, "override.example.com:443")

	override, err := registry.LoadCustomProfile(overridePath)
	require.NoError(t, err)
	assert.Equal(t, []string{"npm-restrictive", overridePath}, override.Lineage)
	assert.Contains(t, override.Network.AllowOutbound, "override.example.com:443")
}

func TestLoadCustomProfileCycleNamesEachFileOnce(t *testing.T) {
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

	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	_, err = registry.LoadCustomProfile(aPath)
	require.Error(t, err)
	assert.Equal(t, 1, strings.Count(err.Error(), "custom profile "))
	assert.Equal(t, 1, strings.Count(err.Error(), "inheritance cycle"))
}

func TestLoadCustomProfilePresetsExpandAfterTheChainMerges(t *testing.T) {
	presetDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(presetDir, "token.yml"), []byte(`
schema_version: 1
kind: preset
name: token
description: allows a token variable
environment:
  allow:
    - MY_TOKEN
`), 0o600))
	presets, err := NewPresetRegistry(WithUserPresetDir(presetDir))
	require.NoError(t, err)

	dir := t.TempDir()
	writeProfileYAML(t, filepath.Join(dir, "parent.yml"), `
name: parent
description: parent with a preset
package_managers: [npm]
presets: [token]
filesystem:
  allow_read:
    - /parent/**
`)
	childPath := writeProfileYAML(t, filepath.Join(dir, "child.yml"), `
name: child
description: child that denies the token
inherits: parent.yml
package_managers: [npm]
environment:
  deny:
    - MY_TOKEN
`)

	registry, err := newDefaultProfileRegistry(WithPresetRegistry(presets))
	require.NoError(t, err)

	child, err := registry.LoadCustomProfile(childPath)
	require.NoError(t, err)
	assert.NotContains(t, child.Environment.Allow, "MY_TOKEN", "the child deny covers the parent's preset allowance")
	assert.Contains(t, child.Environment.Deny, "MY_TOKEN")
	assert.Contains(t, child.Presets, "token")
}

func TestLoadCustomProfileCycleThroughASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs a privilege on Windows")
	}

	dir := t.TempDir()
	require.NoError(t, os.Symlink(".", filepath.Join(dir, "link")))
	aPath := writeProfileYAML(t, filepath.Join(dir, "a.yml"), `
name: a
description: inherits itself through a symlinked directory
inherits: link/a.yml
package_managers: [npm]
filesystem:
  allow_read:
    - /a/**
`)

	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	_, err = registry.LoadCustomProfile(aPath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileInvalid)
	assert.Contains(t, err.Error(), "inheritance cycle")
}

func TestLoadCustomProfilePackageManagersComeFromTheParent(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	dir := t.TempDir()
	writeProfileYAML(t, filepath.Join(dir, "base.yml"), `
name: base
description: base
package_managers: [npm, pnpm]
filesystem:
  allow_read:
    - /base/**
`)
	leafPath := writeProfileYAML(t, filepath.Join(dir, "leaf.yml"), `
name: leaf
description: leaf
inherits: base.yml
network:
  deny_outbound:
    - "*:*"
`)
	leaf, err := registry.LoadCustomProfile(leafPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"npm", "pnpm"}, leaf.PackageManagers)

	ownPath := writeProfileYAML(t, filepath.Join(dir, "own.yml"), `
name: own
description: keeps its own package managers
inherits: base.yml
package_managers: [yarn]
`)
	own, err := registry.LoadCustomProfile(ownPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"yarn"}, own.PackageManagers)

	rootPath := writeProfileYAML(t, filepath.Join(dir, "root.yml"), `
name: root
description: no parent and no package managers
filesystem:
  allow_read:
    - /root/**
`)
	_, err = registry.LoadCustomProfile(rootPath)
	require.ErrorIs(t, err, ErrProfileInvalid)
	assert.Contains(t, err.Error(), "at least one package manager")
}
