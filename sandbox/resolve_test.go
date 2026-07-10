package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveProfileOverrides(t *testing.T) {
	dir := t.TempDir()
	writeUserProfile(t, dir, "my-profile", ".yml")

	registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
	require.NoError(t, err)

	// Use built-in profile that has ${HOME}/${CWD} references
	resolved, err := registry.ResolveProfile("npm-restrictive", ResolveOptions{
		CWD:  "/custom/cwd",
		Home: "/custom/home",
	})
	require.NoError(t, err)

	hasCustomHome := false
	hasCustomCwd := false
	for _, p := range resolved.Filesystem.AllowRead {
		if strings.Contains(p, "/custom/home") {
			hasCustomHome = true
		}
		if strings.Contains(p, "/custom/cwd") {
			hasCustomCwd = true
		}
		assert.NotContains(t, p, "${HOME}")
		assert.NotContains(t, p, "${CWD}")
	}
	assert.True(t, hasCustomHome)
	assert.True(t, hasCustomCwd)
}

func TestResolveProfileProcessEnvFallback(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	resolved, err := registry.ResolveProfile("npm-restrictive", ResolveOptions{})
	require.NoError(t, err)

	found := false
	for _, p := range resolved.Filesystem.AllowRead {
		if strings.HasPrefix(p, home) {
			found = true
			break
		}
	}
	assert.True(t, found, "expected at least one AllowRead path under process home dir")
}

func TestResolveProfileInheritance(t *testing.T) {
	dir := t.TempDir()
	child := `name: child-profile
description: inherits npm-restrictive
inherits: npm-restrictive
package_managers:
  - npm
filesystem:
  allow_read:
    - ${CWD}/extra
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "child-profile.yml"), []byte(child), 0o644))

	registry, err := newDefaultProfileRegistry(WithUserProfileDir(dir))
	require.NoError(t, err)

	resolved, err := registry.ResolveProfile("child-profile", ResolveOptions{
		CWD: "/work",
	})
	require.NoError(t, err)

	found := false
	for _, p := range resolved.Filesystem.AllowRead {
		if p == "/work/extra" {
			found = true
		}
		assert.NotContains(t, p, "${CWD}")
	}
	assert.True(t, found, "expected child rule /work/extra in resolved policy")

	// Inherited parent rules should also be present.
	hasInherited := false
	for _, p := range resolved.Filesystem.AllowRead {
		if p == "/usr" || strings.HasPrefix(p, "/usr/") {
			hasInherited = true
			break
		}
	}
	assert.True(t, hasInherited, "expected inherited builtin AllowRead rule")
}

func TestResolveProfileDoesNotMutateRegistry(t *testing.T) {
	registry, err := newDefaultProfileRegistry()
	require.NoError(t, err)

	before, err := registry.GetProfile("npm-restrictive")
	require.NoError(t, err)

	originalAllowRead := append([]string(nil), before.Filesystem.AllowRead...)

	_, err = registry.ResolveProfile("npm-restrictive", ResolveOptions{
		CWD:  "/x",
		Home: "/y",
	})
	require.NoError(t, err)

	after, err := registry.GetProfile("npm-restrictive")
	require.NoError(t, err)
	assert.Equal(t, originalAllowRead, after.Filesystem.AllowRead, "registry profile must not be mutated")
}

func TestExpandPolicyPathsIsolatesBoolPointers(t *testing.T) {
	source := &SandboxPolicy{
		Name:                "ptr-isolation",
		PackageManagers:     []string{"npm"},
		Filesystem:          FilesystemPolicy{AllowRead: []string{"/tmp"}},
		AllowGitConfig:      utils.PtrTo(true),
		AllowPTY:            utils.PtrTo(true),
		AllowNetworkBind:    utils.PtrTo(true),
		NetworkViaProxyOnly: utils.PtrTo(true),
		AllowDirectDNS:      utils.PtrTo(true),
	}

	resolved, err := expandPolicyPaths(source, ResolveOptions{CWD: "/x", Home: "/y"})
	require.NoError(t, err)

	fields := []struct {
		name             string
		source, resolved *bool
	}{
		{"AllowGitConfig", source.AllowGitConfig, resolved.AllowGitConfig},
		{"AllowPTY", source.AllowPTY, resolved.AllowPTY},
		{"AllowNetworkBind", source.AllowNetworkBind, resolved.AllowNetworkBind},
		{"NetworkViaProxyOnly", source.NetworkViaProxyOnly, resolved.NetworkViaProxyOnly},
		{"AllowDirectDNS", source.AllowDirectDNS, resolved.AllowDirectDNS},
	}
	for _, f := range fields {
		assert.NotSame(t, f.source, f.resolved, f.name)
		assert.Equal(t, *f.source, *f.resolved, f.name)
	}
}
