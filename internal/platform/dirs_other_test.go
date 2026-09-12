//go:build !windows && !darwin

package platform

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHomeDirsFollowXDGDefaults(t *testing.T) {
	assert.Equal(t, Dirs{
		Config: "/root/.config",
		Cache:  "/root/.cache",
		Data:   "/root/.local/share",
	}, HomeDirs("/root"))
}

func TestUserDataDirHonorsXdgDataHome(t *testing.T) {
	t.Setenv("HOME", "/home/victim")
	t.Setenv("XDG_DATA_HOME", "/custom/data")

	dir, err := UserDataDir()
	require.NoError(t, err)
	assert.Equal(t, "/custom/data", dir)
}

func TestUserDataDirDefaultsToLocalShare(t *testing.T) {
	t.Setenv("HOME", "/home/victim")
	t.Setenv("XDG_DATA_HOME", "")

	dir, err := UserDataDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("/home/victim", ".local", "share"), dir)
}

func TestSystemDirs(t *testing.T) {
	assert.Equal(t, "/etc/safedep/pmg", SystemConfigDir())
	assert.Equal(t, "/usr/local/lib/pmg/bin", SystemBinDir())
	assert.Equal(t, "/etc/profile.d/pmg.sh", SystemProfilePath())
	assert.False(t, UserConfigDirRoams)
}
