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

func TestEnvDoesNotOverrideLockedConfig(t *testing.T) {
	globalDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("paranoid: true\nglobal_lockdown: true\n"), 0o644))

	useManagedConfigDir(t, globalDir)
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	t.Setenv("PMG_PARANOID", "false")
	initConfig()

	require.True(t, Get().IsLocked())
	assert.True(t, Get().Config.Paranoid, "PMG_PARANOID must not override a locked config")
}

func TestEnvOverridesManagedConfigWhenNotLocked(t *testing.T) {
	globalDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("paranoid: true\n"), 0o644))

	useManagedConfigDir(t, globalDir)
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	t.Setenv("PMG_PARANOID", "false")
	initConfig()

	require.True(t, Get().IsManaged())
	require.False(t, Get().IsLocked())
	assert.False(t, Get().Config.Paranoid, "without lockdown, PMG_PARANOID overrides the managed baseline")
}

func TestEnvOverridesUserConfigWhenNotManaged(t *testing.T) {
	userDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(userDir, "config.yml"), []byte("paranoid: true\n"), 0o644))

	useManagedConfigDir(t, t.TempDir()) // empty global dir -> not managed
	t.Setenv("PMG_CONFIG_DIR", userDir)
	t.Setenv("PMG_PARANOID", "false")
	initConfig()

	require.False(t, Get().IsManaged())
	assert.False(t, Get().Config.Paranoid, "PMG_PARANOID should override the per-user config")
}

func TestInsecureInstallationEnvIgnoredWhenLocked(t *testing.T) {
	globalDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("global_lockdown: true\n"), 0o644))

	useManagedConfigDir(t, globalDir)
	t.Setenv("PMG_INSECURE_INSTALLATION", "true")
	initConfig()

	require.True(t, Get().IsLocked())
	assert.False(t, Get().InsecureInstallation, "PMG_INSECURE_INSTALLATION must not bypass a locked config")
}

func TestInsecureInstallationHonoredWhenManagedNotLocked(t *testing.T) {
	globalDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("paranoid: true\n"), 0o644))

	useManagedConfigDir(t, globalDir)
	t.Setenv("PMG_INSECURE_INSTALLATION", "true")
	initConfig()

	require.True(t, Get().IsManaged())
	require.False(t, Get().IsLocked())
	assert.True(t, Get().InsecureInstallation, "without lockdown, PMG_INSECURE_INSTALLATION is honored")
}

func TestInsecureInstallationEnvHonoredWhenNotManaged(t *testing.T) {
	useManagedConfigDir(t, t.TempDir()) // empty global dir -> not managed
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	t.Setenv("PMG_INSECURE_INSTALLATION", "true")
	initConfig()

	require.False(t, Get().IsManaged())
	assert.True(t, Get().InsecureInstallation)
}

func TestMalformedGlobalConfigFailsClosed(t *testing.T) {
	globalDir := t.TempDir()
	// Present but unparseable YAML ("mapping values not allowed in this context").
	require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("a: b: c\n"), 0o644))

	useManagedConfigDir(t, globalDir)
	initConfig()

	require.True(t, Get().IsManaged())
	assert.True(t, Get().IsLocked(), "a present but unparseable global config must fail closed (locked)")
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
