package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearUserEnv unsets every variable that names a directory of the user, as
// a systemd unit without User= does.
func clearUserEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"PMG_CONFIG_DIR", "PMG_CACHE_DIR", "SUDO_USER",
		"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
		"USERPROFILE", "APPDATA", "LOCALAPPDATA",
	} {
		t.Setenv(key, "")
	}
}

// The help of the UserDirUnresolved error names PMG_CONFIG_DIR and
// PMG_CACHE_DIR. The two must be enough on every OS, including Windows, where
// the event log otherwise sits beside the data directory.
func TestInitConfigWithOnlyPMGDirs(t *testing.T) {
	t.Cleanup(initConfig)
	clearUserEnv(t)
	withoutCurrentUserHome(t)
	configDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", configDir)
	t.Setenv("PMG_CACHE_DIR", t.TempDir())

	initConfig()
	require.NoError(t, InitError())
	assert.Equal(t, filepath.Join(configDir, pmgDefaultLogDir), Get().EventLogDir())
}
