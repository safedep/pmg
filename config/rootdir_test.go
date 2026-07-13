package config

import (
	"os/user"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withEuid(t *testing.T, euid int) {
	t.Helper()
	orig := configGeteuid
	configGeteuid = func() int { return euid }
	t.Cleanup(func() { configGeteuid = orig })
}

func poisonUserEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PMG_CONFIG_DIR", "")
	t.Setenv("PMG_CACHE_DIR", "")
	t.Setenv("HOME", "/home/victim")
	t.Setenv("XDG_CONFIG_HOME", "/home/victim/.config")
	t.Setenv("XDG_CACHE_HOME", "/home/victim/.cache")
}

func TestConfigDirAsRootIgnoresPreservedHome(t *testing.T) {
	poisonUserEnv(t)
	withEuid(t, 0)

	dir, err := configDir()
	require.NoError(t, err)

	rootUser, err := user.LookupId("0")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(dir, rootUser.HomeDir), "expected %s under root home %s", dir, rootUser.HomeDir)
	assert.NotContains(t, dir, "/home/victim")
}

func TestConfigDirAsNonRootUsesEnvHome(t *testing.T) {
	poisonUserEnv(t)
	withEuid(t, 1000)

	dir, err := configDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "/home/victim")
}

func TestConfigDirEnvOverrideWinsForRoot(t *testing.T) {
	poisonUserEnv(t)
	t.Setenv("PMG_CONFIG_DIR", "/custom/pmg")
	withEuid(t, 0)

	dir, err := configDir()
	require.NoError(t, err)
	assert.Equal(t, "/custom/pmg", dir)
}

func TestCacheDirAsRootIgnoresPreservedHome(t *testing.T) {
	poisonUserEnv(t)
	withEuid(t, 0)

	dir, err := cacheDir()
	require.NoError(t, err)

	rootUser, err := user.LookupId("0")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(dir, rootUser.HomeDir), "expected %s under root home %s", dir, rootUser.HomeDir)
	assert.NotContains(t, dir, "/home/victim")
}

func TestCacheDirAsNonRootUsesEnvHome(t *testing.T) {
	poisonUserEnv(t)
	withEuid(t, 1000)

	dir, err := cacheDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "/home/victim")
}

func TestRootDirsFallBackToEnvWhenPasswdUnavailable(t *testing.T) {
	poisonUserEnv(t)
	withEuid(t, 0)

	origConfig, origCache := rootConfigDirResolver, rootCacheDirResolver
	rootConfigDirResolver = func() (string, error) { return "", assert.AnError }
	rootCacheDirResolver = func() (string, error) { return "", assert.AnError }
	t.Cleanup(func() {
		rootConfigDirResolver, rootCacheDirResolver = origConfig, origCache
	})

	dir, err := configDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "/home/victim")

	dir, err = cacheDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "/home/victim")
}
