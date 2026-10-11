package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// os.UserConfigDir rejects a relative XDG_CONFIG_HOME even when HOME is set.
// The config directory must then derive from HOME, like the cache directory,
// and not from the user database.
func TestConfigDirWithRelativeXDGUsesHome(t *testing.T) {
	clearUserEnv(t)
	withPrivilege(t, false)
	withCurrentUserHome(t, "/home/fromdb")
	t.Setenv("HOME", "/srv/build")
	t.Setenv("XDG_CONFIG_HOME", "relative")

	dir, err := configDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("/srv/build", ".config", pmgDefaultHomeRelativePath), dir)
}
