package shim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func useSystemPaths(t *testing.T, dir string) {
	t.Helper()
	systemBinDirOverride = filepath.Join(dir, "bin")
	systemProfilePathOverride = filepath.Join(dir, "profile.d", "pmg.sh")
	t.Cleanup(func() {
		systemBinDirOverride = ""
		systemProfilePathOverride = ""
	})
}

func TestSystemShimManagerInstallAndRemove(t *testing.T) {
	root := t.TempDir()
	useSystemPaths(t, root)

	mgr, err := NewSystemShimManager()
	require.NoError(t, err)
	assert.True(t, mgr.config.SkipShellRc)
	assert.True(t, mgr.config.ManageProfile)
	assert.Equal(t, SystemBinDir(), mgr.GetBinDir())

	require.NoError(t, mgr.Install())
	assert.True(t, SystemShimsInstalled())
	assert.True(t, SystemProfileInstalled())

	npmShim := filepath.Join(SystemBinDir(), "npm")
	content, err := os.ReadFile(npmShim)
	require.NoError(t, err)
	assert.Contains(t, string(content), "export PMG_SHIM_PATH")

	profile, err := os.ReadFile(SystemProfilePath())
	require.NoError(t, err)
	assert.Contains(t, string(profile), mgr.GetBinDir())
	assert.Contains(t, string(profile), systemProfileMarker)

	require.NoError(t, mgr.Install())
	profile2, err := os.ReadFile(SystemProfilePath())
	require.NoError(t, err)
	assert.Equal(t, string(profile), string(profile2))

	require.NoError(t, mgr.Remove())
	assert.False(t, SystemShimsInstalled())
	assert.False(t, SystemProfileInstalled())
	require.NoError(t, mgr.Remove())
}

func TestSystemShimManagerDoesNotTouchUserRc(t *testing.T) {
	root := t.TempDir()
	useSystemPaths(t, root)

	home := t.TempDir()
	bashrc := filepath.Join(home, ".bashrc")
	require.NoError(t, os.WriteFile(bashrc, []byte("# user bashrc\n"), 0o644))

	mgr, err := NewSystemShimManager()
	require.NoError(t, err)
	mgr.config.HomeDir = home
	require.NoError(t, mgr.Install())

	content, err := os.ReadFile(bashrc)
	require.NoError(t, err)
	assert.Equal(t, "# user bashrc\n", string(content))
}
