//go:build unix

package config

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
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

func withoutRootHome(t *testing.T) {
	t.Helper()
	orig := rootHomeDirResolver
	rootHomeDirResolver = func() (string, error) { return "", assert.AnError }
	t.Cleanup(func() { rootHomeDirResolver = orig })
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

	withoutRootHome(t)

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

	withoutRootHome(t)

	home, err := UserHomeDir()
	require.NoError(t, err)
	assert.Equal(t, "/home/victim", home)
}

func TestUserDirsFallBackToPasswdHomeWithoutEnv(t *testing.T) {
	const home = "/home/fromdb"
	want := platform.HomeDirs(home)

	resolvers := []struct {
		name    string
		resolve func() (string, error)
		want    string
	}{
		{"config", configDir, filepath.Join(want.Config, pmgDefaultHomeRelativePath)},
		{"cache", cacheDir, filepath.Join(want.Cache, pmgDefaultHomeRelativePath)},
		{"data", UserDataDir, filepath.Join(want.Data, pmgDefaultHomeRelativePath)},
		{"home", UserHomeDir, home},
	}

	for _, privileged := range []bool{false, true} {
		for _, r := range resolvers {
			t.Run(fmt.Sprintf("%s/privileged=%t", r.name, privileged), func(t *testing.T) {
				clearUserEnv(t)
				withPrivilege(t, privileged)
				withCurrentUserHome(t, home)

				dir, err := r.resolve()
				require.NoError(t, err)
				assert.Equal(t, r.want, dir)
			})
		}
	}
}

func TestUserDirsFallBackPerDirectory(t *testing.T) {
	clearUserEnv(t)
	withPrivilege(t, false)
	withCurrentUserHome(t, "/home/fromdb")
	t.Setenv("PMG_CONFIG_DIR", "/custom/pmg")

	dir, err := configDir()
	require.NoError(t, err)
	assert.Equal(t, "/custom/pmg", dir)

	dir, err = cacheDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(platform.HomeDirs("/home/fromdb").Cache, pmgDefaultHomeRelativePath), dir)
}

func TestUserDirsUnderSudoFallBackToPasswdHomeWithoutRootEntry(t *testing.T) {
	clearUserEnv(t)
	withPrivilege(t, true)
	t.Setenv("SUDO_USER", "victim")
	withoutRootHome(t)
	withCurrentUserHome(t, "/home/fromdb")

	dir, err := configDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(platform.HomeDirs("/home/fromdb").Config, pmgDefaultHomeRelativePath), dir)
}

func TestUserDirsPreferEnvOverPasswdHome(t *testing.T) {
	poisonUserEnv(t)
	withPrivilege(t, false)
	withCurrentUserHome(t, "/home/fromdb")

	for _, resolve := range []func() (string, error){configDir, cacheDir, UserDataDir, UserHomeDir} {
		dir, err := resolve()
		require.NoError(t, err)
		assert.Contains(t, dir, "/home/victim")
	}
}

func TestUserDirsWithoutEnvOrPasswdHomeReturnUsefulError(t *testing.T) {
	clearUserEnv(t)
	withPrivilege(t, false)
	withoutCurrentUserHome(t)

	for _, resolve := range []func() (string, error){configDir, cacheDir, UserDataDir, UserHomeDir} {
		_, err := resolve()
		requireUserDirUnresolved(t, err)
	}
}

func TestInitConfigWithoutUserHome(t *testing.T) {
	t.Cleanup(initConfig)

	t.Run("records an error and does not panic", func(t *testing.T) {
		clearUserEnv(t)
		withPrivilege(t, false)
		withoutCurrentUserHome(t)

		require.NotPanics(t, initConfig)
		requireUserDirUnresolved(t, InitError())
		assert.NotNil(t, Get())
	})

	t.Run("still loads the managed config", func(t *testing.T) {
		globalDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("paranoid: true\n"), 0o644))
		clearUserEnv(t)
		withPrivilege(t, false)
		withoutCurrentUserHome(t)
		useManagedConfigDir(t, globalDir)

		initConfig()
		requireUserDirUnresolved(t, InitError())
		assert.Equal(t, filepath.Join(globalDir, "config.yml"), Get().ConfigFilePath())
		assert.True(t, Get().Config.Paranoid)
	})
}

func requireUserDirUnresolved(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	ue, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok, "%v", err)
	assert.Equal(t, errcodes.UserDirUnresolved, ue.Code())
	assert.Contains(t, ue.Help(), "PMG_CONFIG_DIR")
}
