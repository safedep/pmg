package platform

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHomeDirsFollowLibraryLayout(t *testing.T) {
	assert.Equal(t, Dirs{
		Config: "/var/root/Library/Application Support",
		Cache:  "/var/root/Library/Caches",
		Data:   "/var/root/Library/Application Support",
	}, HomeDirs("/var/root"))
}

func TestUserDataDirIsTheConfigDir(t *testing.T) {
	want, err := os.UserConfigDir()
	require.NoError(t, err)

	dir, err := UserDataDir()
	require.NoError(t, err)
	assert.Equal(t, want, dir)
}

func TestSystemDirs(t *testing.T) {
	assert.Equal(t, "/Library/Application Support/safedep/pmg", SystemConfigDir())
	assert.Equal(t, "/usr/local/lib/pmg/bin", SystemBinDir())
	assert.Equal(t, "/etc/profile.d/pmg.sh", SystemProfilePath())
	assert.False(t, UserConfigDirRoams)
}
