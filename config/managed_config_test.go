package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// useManagedConfigDir points the globally managed config at dir for the test,
// and restores the default resolution afterwards.
func useManagedConfigDir(t *testing.T, dir string) {
	t.Helper()
	globalConfigDirOverride = dir
	t.Cleanup(func() {
		globalConfigDirOverride = ""
		initConfig()
	})
}

func TestManagedConfigTakesPrecedenceAndIgnoresUserFile(t *testing.T) {
	globalDir := t.TempDir()
	userDir := t.TempDir()

	// Global file sets paranoid=true (default is false). User file sets
	// transitive=false (default is true) and must be ignored entirely.
	require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("paranoid: true\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(userDir, "config.yml"), []byte("transitive: false\n"), 0o644))

	useManagedConfigDir(t, globalDir)
	t.Setenv("PMG_CONFIG_DIR", userDir)
	initConfig()

	cfg := Get()
	assert.True(t, cfg.IsManaged())
	assert.Equal(t, filepath.Join(globalDir, "config.yml"), cfg.ConfigFilePath())
	assert.Equal(t, filepath.Join(userDir, "config.yml"), cfg.UserConfigFilePath())

	assert.True(t, cfg.Config.Paranoid, "value should come from the global file")
	assert.True(t, cfg.Config.Transitive, "user file must be ignored, so this stays at the template default")
}

func TestManagedConfigFallsBackToUserWhenGlobalAbsent(t *testing.T) {
	globalDir := t.TempDir() // no config.yml written here
	userDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(userDir, "config.yml"), []byte("paranoid: true\n"), 0o644))

	useManagedConfigDir(t, globalDir)
	t.Setenv("PMG_CONFIG_DIR", userDir)
	initConfig()

	cfg := Get()
	assert.False(t, cfg.IsManaged())
	assert.Equal(t, filepath.Join(userDir, "config.yml"), cfg.ConfigFilePath())
	assert.True(t, cfg.Config.Paranoid, "value should come from the user file")
}

func TestWriteTemplateConfigNoOpWhenManaged(t *testing.T) {
	globalDir := t.TempDir()
	userDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("paranoid: true\n"), 0o644))

	useManagedConfigDir(t, globalDir)
	t.Setenv("PMG_CONFIG_DIR", userDir)
	initConfig()

	require.NoError(t, WriteTemplateConfig())
	assert.NoFileExists(t, filepath.Join(userDir, "config.yml"), "managed mode must not create a per-user config")
}

func TestSetConfigValueRefusedWhenManaged(t *testing.T) {
	globalDir := t.TempDir()
	userDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("paranoid: true\n"), 0o644))

	useManagedConfigDir(t, globalDir)
	t.Setenv("PMG_CONFIG_DIR", userDir)
	initConfig()

	err := SetConfigValue("paranoid", "false")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "globally managed")
	assert.NoFileExists(t, filepath.Join(userDir, "config.yml"))
}

func TestRemoveUserConfigFileNeverTouchesGlobal(t *testing.T) {
	globalDir := t.TempDir()
	userDir := t.TempDir()
	globalFile := filepath.Join(globalDir, "config.yml")
	userFile := filepath.Join(userDir, "config.yml")
	require.NoError(t, os.WriteFile(globalFile, []byte("paranoid: true\n"), 0o644))
	require.NoError(t, os.WriteFile(userFile, []byte("transitive: false\n"), 0o644))

	useManagedConfigDir(t, globalDir)
	t.Setenv("PMG_CONFIG_DIR", userDir)
	initConfig()

	require.NoError(t, RemoveUserConfigFile())
	assert.NoFileExists(t, userFile, "per-user file should be removed")
	assert.FileExists(t, globalFile, "globally managed file must be left intact")
}
