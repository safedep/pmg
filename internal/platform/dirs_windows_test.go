package platform

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestHomeDirsFollowAppDataLayout(t *testing.T) {
	assert.Equal(t, Dirs{
		Config: `C:\Users\root\AppData\Roaming`,
		Cache:  `C:\Users\root\AppData\Local`,
		Data:   `C:\Users\root\AppData\Local`,
	}, HomeDirs(`C:\Users\root`))
}

func TestUserCacheAndDataDirsFallBackToUserProfile(t *testing.T) {
	t.Setenv("LOCALAPPDATA", `C:\Users\dev\AppData\Local`)
	t.Setenv("USERPROFILE", `C:\Users\dev`)
	for _, resolve := range []func() (string, error){UserCacheDir, UserDataDir} {
		dir, err := resolve()
		require.NoError(t, err)
		assert.Equal(t, `C:\Users\dev\AppData\Local`, dir)
	}

	t.Setenv("LOCALAPPDATA", "")
	for _, resolve := range []func() (string, error){UserCacheDir, UserDataDir} {
		dir, err := resolve()
		require.NoError(t, err)
		assert.Equal(t, `C:\Users\dev`, dir)
	}

	t.Setenv("USERPROFILE", "")
	_, err := UserCacheDir()
	assert.ErrorContains(t, err, "neither LOCALAPPDATA nor USERPROFILE is set")
	assert.True(t, UserConfigDirRoams)
}

// The system paths come from the shell, not from variables the user's
// process controls. A directory of the user's choosing must not become the
// managed config or the first entry of the machine PATH.
func TestSystemDirsIgnoreTheEnvironment(t *testing.T) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	require.NoError(t, err)
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	require.NoError(t, err)

	t.Setenv("ProgramFiles", `C:\Users\dev\evil`)
	t.Setenv("PROGRAMDATA", `C:\Users\dev\evil`)
	assert.Equal(t, filepath.Join(programFiles, `safedep\pmg\bin`), SystemBinDir())
	assert.Equal(t, filepath.Join(programData, `safedep\pmg`), SystemConfigDir())
	assert.Empty(t, SystemProfilePath())
}

func TestUnderKnownFolderIsEmptyWhenUnresolved(t *testing.T) {
	assert.Empty(t, underKnownFolder("", "safedep", "pmg"))
	assert.Equal(t, `C:\ProgramData\safedep\pmg`, underKnownFolder(`C:\ProgramData`, "safedep", "pmg"))
}
