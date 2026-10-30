//go:build unix

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/internal/platform/platformtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secureManagedConfigForTest makes the runtime accept a managed config that
// the test user owns. The mode and link checks still apply.
func secureManagedConfigForTest(t *testing.T, _ string) {
	t.Helper()
	platformtest.TrustCurrentUser(t)
}

func TestWriteSystemTemplateConfigReadableUnderRestrictiveUmask(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mode repair only runs as root")
	}

	oldUmask := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(oldUmask) })

	globalDir := filepath.Join(t.TempDir(), "safedep", "pmg")
	useManagedConfigDir(t, globalDir)

	require.NoError(t, WriteSystemTemplateConfig())

	fileInfo, err := os.Stat(filepath.Join(globalDir, "config.yml"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fileInfo.Mode().Perm(),
		"managed config must stay world-readable regardless of the installer's umask")

	for _, dir := range []string{globalDir, filepath.Dir(globalDir)} {
		dirInfo, err := os.Stat(dir)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o755), dirInfo.Mode().Perm(),
			"managed config directories must stay world-searchable: %s", dir)
	}
}

// The runtime obeys the managed config only when the system owner owns the
// file and both directories above it, and no other account may write them.
// A link at the managed path never governs.
func TestManagedConfigFileRequiresSystemControl(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "safedep", "pmg")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, "config.yml")
	require.NoError(t, os.WriteFile(path, []byte("paranoid: true\n"), 0o644))
	for _, p := range []string{filepath.Dir(dir), dir} {
		require.NoError(t, os.Chmod(p, 0o755))
	}
	require.NoError(t, os.Chmod(path, 0o644))
	useManagedConfigDir(t, dir)

	got, ok := managedConfigFile()
	require.True(t, ok)
	require.Equal(t, path, got)

	for _, p := range []string{filepath.Dir(dir), dir, path} {
		require.NoError(t, os.Chmod(p, 0o775))
		_, ok = managedConfigFile()
		assert.False(t, ok, "a managed config is ignored when the group may write %s", p)
		require.NoError(t, os.Chmod(p, 0o755))
	}

	orig := platform.SystemOwnerUID
	platform.SystemOwnerUID = uint32(os.Getuid()) + 1
	_, ok = managedConfigFile()
	assert.False(t, ok, "a managed config that another account owns is ignored")
	platform.SystemOwnerUID = orig

	target := filepath.Join(t.TempDir(), "elsewhere.yml")
	require.NoError(t, os.WriteFile(target, []byte("paranoid: false\n"), 0o644))
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Symlink(target, path))
	_, ok = managedConfigFile()
	assert.False(t, ok, "a link at the managed path is ignored")
}
