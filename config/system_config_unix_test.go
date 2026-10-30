//go:build unix

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
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

// managedTree writes a managed config at dir/config.yml with the modes the
// install sets, and points the managed lookup at dir.
func managedTree(t *testing.T) (dir, path string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "safedep", "pmg")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path = filepath.Join(dir, "config.yml")
	require.NoError(t, os.WriteFile(path, []byte("global_lockdown: true\nparanoid: true\n"), 0o644))
	require.NoError(t, os.Chmod(filepath.Dir(dir), 0o755))
	require.NoError(t, os.Chmod(dir, 0o755))
	require.NoError(t, os.Chmod(path, 0o644))
	useManagedConfigDir(t, dir)
	return dir, path
}

// giveToAnotherAccount makes path belong to an account the check does not
// trust. Root changes the owner. Another user stops trusting itself.
func giveToAnotherAccount(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		require.NoError(t, os.Lchown(path, 65534, 65534))
		return
	}
	t.Cleanup(platform.TrustOwnerForTest(uint32(os.Getuid()) + 1))
}

// The runtime obeys the managed config only when the system account owns
// the file and every directory above it, and no other account may write
// them. A link is followed only when the system account owns it.
func TestManagedConfigFileRequiresSystemControl(t *testing.T) {
	tests := []struct {
		name    string
		change  func(t *testing.T, dir, path string)
		wantErr string
	}{
		{name: "the install modes", change: func(*testing.T, string, string) {}},
		{
			name:    "the group may write the vendor directory",
			change:  func(t *testing.T, dir, _ string) { require.NoError(t, os.Chmod(filepath.Dir(dir), 0o775)) },
			wantErr: "safedep lets its group write it",
		},
		{
			name:    "every user may write the product directory",
			change:  func(t *testing.T, dir, _ string) { require.NoError(t, os.Chmod(dir, 0o757)) },
			wantErr: "pmg lets every user write it",
		},
		{
			name:    "the group may write the file",
			change:  func(t *testing.T, _, path string) { require.NoError(t, os.Chmod(path, 0o664)) },
			wantErr: "config.yml lets its group write it",
		},
		{
			name:    "another account owns the file",
			change:  func(t *testing.T, _, path string) { giveToAnotherAccount(t, path) },
			wantErr: "not by root",
		},
		{
			name: "a link of the system account to a controlled file",
			change: func(t *testing.T, dir, path string) {
				real := filepath.Join(dir, "real.yml")
				require.NoError(t, os.Rename(path, real))
				require.NoError(t, os.Symlink("real.yml", path))
			},
		},
		{
			name: "a link of the system account to a file the group may write",
			change: func(t *testing.T, dir, path string) {
				real := filepath.Join(dir, "real.yml")
				require.NoError(t, os.Rename(path, real))
				require.NoError(t, os.Chmod(real, 0o664))
				require.NoError(t, os.Symlink("real.yml", path))
			},
			wantErr: "real.yml lets its group write it",
		},
		{
			name: "a directory at the managed path",
			change: func(t *testing.T, _, path string) {
				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Mkdir(path, 0o755))
			},
			wantErr: "is not a regular file",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := managedTree(t)
			tc.change(t, dir, path)

			got, err := managedConfigFile()
			if tc.wantErr == "" {
				require.NoError(t, err)
				assert.Equal(t, path, got)
				return
			}
			assert.Empty(t, got)
			require.ErrorContains(t, err, tc.wantErr)
			usefulErr, ok := usefulerror.AsUsefulError(err)
			require.True(t, ok)
			assert.Equal(t, errcodes.PermissionDenied, usefulErr.Code())
			assert.Contains(t, usefulErr.HumanError(), path)
			assert.Contains(t, usefulErr.Help(), "sudo chown root")
		})
	}
}

func TestManagedConfigFileAbsent(t *testing.T) {
	useManagedConfigDir(t, filepath.Join(t.TempDir(), "safedep", "pmg"))

	got, err := managedConfigFile()
	assert.NoError(t, err)
	assert.Empty(t, got)
}

// A managed config that PMG ignores drops global_lockdown. The runtime keeps
// the reason, so the CLI can print it after package init.
func TestIgnoredManagedConfigIsReported(t *testing.T) {
	_, path := managedTree(t)
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	initConfig()
	require.True(t, Get().IsLocked())
	assert.Empty(t, Get().ManagedConfigWarning())

	require.NoError(t, os.Chmod(path, 0o666))
	initConfig()

	cfg := Get()
	assert.False(t, cfg.IsManaged())
	assert.False(t, cfg.IsLocked())
	require.Error(t, cfg.ManagedConfigError())
	warning := cfg.ManagedConfigWarning()
	assert.Contains(t, warning, "The managed config "+path+" does not apply")
	assert.Contains(t, warning, "config.yml lets its group write it")
	assert.Contains(t, warning, "sudo chmod go-w")
}

// PrepareSystemDir leaves an existing directory unchanged. The install then
// fails, because the runtime would ignore the file it wrote.
func TestWriteSystemTemplateConfigRefusesAnUncontrolledDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "safedep", "pmg")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.Chmod(filepath.Dir(dir), 0o775))
	useManagedConfigDir(t, dir)

	err := WriteSystemTemplateConfig()
	require.ErrorContains(t, err, "safedep lets its group write it")
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.PermissionDenied, usefulErr.Code())
	assert.Contains(t, usefulErr.Help(), "sudo chown root")
}
