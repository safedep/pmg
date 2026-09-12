//go:build unix

package config

import (
	"os/user"
	"strings"
	"testing"

	"github.com/safedep/pmg/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withPrivilege(t *testing.T, privileged bool) {
	t.Helper()
	orig := platform.IsPrivileged
	platform.IsPrivileged = func() bool { return privileged }
	t.Cleanup(func() { platform.IsPrivileged = orig })
}

func poisonUserEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PMG_CONFIG_DIR", "")
	t.Setenv("PMG_CACHE_DIR", "")
	t.Setenv("HOME", "/home/victim")
	t.Setenv("XDG_CONFIG_HOME", "/home/victim/.config")
	t.Setenv("XDG_CACHE_HOME", "/home/victim/.cache")
	t.Setenv("XDG_DATA_HOME", "/home/victim/.local/share")
}

func TestConfigDirUnderSudoIgnoresPreservedHome(t *testing.T) {
	poisonUserEnv(t)
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "victim")

	dir, err := configDir()
	require.NoError(t, err)

	rootUser, err := user.LookupId("0")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(dir, rootUser.HomeDir), "expected %s under root home %s", dir, rootUser.HomeDir)
	assert.NotContains(t, dir, "/home/victim")
}

func TestConfigDirGenuineRootHonorsEnv(t *testing.T) {
	// Root without sudo (SUDO_USER unset) is the intended user, e.g. a golden
	// Docker image that deliberately sets XDG_CONFIG_HOME. It must not divert.
	poisonUserEnv(t)
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "")

	dir, err := configDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "/home/victim")
}

func TestConfigDirAsNonRootUsesEnvHome(t *testing.T) {
	poisonUserEnv(t)
	withPrivilege(t, false)

	dir, err := configDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "/home/victim")
}

func TestConfigDirEnvOverrideWinsUnderSudo(t *testing.T) {
	poisonUserEnv(t)
	t.Setenv("PMG_CONFIG_DIR", "/custom/pmg")
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "victim")

	dir, err := configDir()
	require.NoError(t, err)
	assert.Equal(t, "/custom/pmg", dir)
}

func TestCacheDirUnderSudoIgnoresPreservedHome(t *testing.T) {
	poisonUserEnv(t)
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "victim")

	dir, err := cacheDir()
	require.NoError(t, err)

	rootUser, err := user.LookupId("0")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(dir, rootUser.HomeDir), "expected %s under root home %s", dir, rootUser.HomeDir)
	assert.NotContains(t, dir, "/home/victim")
}

func TestCacheDirGenuineRootHonorsEnv(t *testing.T) {
	poisonUserEnv(t)
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "")

	dir, err := cacheDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "/home/victim")
}

func TestCacheDirAsNonRootUsesEnvHome(t *testing.T) {
	poisonUserEnv(t)
	withPrivilege(t, false)

	dir, err := cacheDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "/home/victim")
}

func TestRootDirsFallBackToEnvWhenPasswdUnavailable(t *testing.T) {
	poisonUserEnv(t)
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "victim")

	orig := rootHomeDirResolver
	rootHomeDirResolver = func() (string, error) { return "", assert.AnError }
	t.Cleanup(func() { rootHomeDirResolver = orig })

	dir, err := configDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "/home/victim")

	dir, err = cacheDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "/home/victim")

	dir, err = UserDataDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "/home/victim")
}

func TestUserDataDirUnderSudoIgnoresPreservedHome(t *testing.T) {
	poisonUserEnv(t)
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "victim")

	dir, err := UserDataDir()
	require.NoError(t, err)

	rootUser, err := user.LookupId("0")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(dir, rootUser.HomeDir), "expected %s under root home %s", dir, rootUser.HomeDir)
	assert.NotContains(t, dir, "/home/victim")
}

func TestUserDataDirAsNonRootUsesEnvHome(t *testing.T) {
	poisonUserEnv(t)
	withPrivilege(t, false)

	dir, err := UserDataDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "/home/victim")
}

func TestUserHomeDirUnderSudoIgnoresPreservedHome(t *testing.T) {
	poisonUserEnv(t)
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "victim")

	home, err := UserHomeDir()
	require.NoError(t, err)

	rootUser, err := user.LookupId("0")
	require.NoError(t, err)
	assert.Equal(t, rootUser.HomeDir, home)
	assert.NotContains(t, home, "/home/victim")
}

func TestUserHomeDirAsNonRootUsesEnvHome(t *testing.T) {
	poisonUserEnv(t)
	withPrivilege(t, false)

	home, err := UserHomeDir()
	require.NoError(t, err)
	assert.Equal(t, "/home/victim", home)
}

func TestUserHomeDirFallsBackToEnvWhenPasswdUnavailable(t *testing.T) {
	poisonUserEnv(t)
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "victim")

	orig := rootHomeDirResolver
	rootHomeDirResolver = func() (string, error) { return "", assert.AnError }
	t.Cleanup(func() { rootHomeDirResolver = orig })

	home, err := UserHomeDir()
	require.NoError(t, err)
	assert.Equal(t, "/home/victim", home)
}
