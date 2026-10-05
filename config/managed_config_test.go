package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// useManagedConfigDir points the globally managed config at dir for the test,
// and restores the default resolution afterwards. On Windows the runtime
// obeys a managed config only under administrative control, so the
// directory and its file are secured as the install would leave them.
func useManagedConfigDir(t *testing.T, dir string) {
	t.Helper()
	globalConfigDirOverride = dir
	t.Cleanup(func() {
		globalConfigDirOverride = ""
		initConfig()
	})
	secureManagedConfigForTest(t, dir)
}

func TestManagedConfigTakesPrecedenceAndIgnoresUserFile(t *testing.T) {
	globalDir := t.TempDir()
	userDir := t.TempDir()

	// Global file sets paranoid=true (default is false). User file sets
	// skip_event_logging=true (default is false) and must be ignored entirely.
	require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("paranoid: true\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(userDir, "config.yml"), []byte("skip_event_logging: true\n"), 0o644))

	useManagedConfigDir(t, globalDir)
	t.Setenv("PMG_CONFIG_DIR", userDir)
	initConfig()

	cfg := Get()
	assert.True(t, cfg.IsManaged())
	assert.Equal(t, filepath.Join(globalDir, "config.yml"), cfg.ConfigFilePath())
	assert.Equal(t, filepath.Join(userDir, "config.yml"), cfg.UserConfigFilePath())

	assert.True(t, cfg.Config.Paranoid, "value should come from the global file")
	assert.False(t, cfg.Config.SkipEventLogging, "user file must be ignored, so this stays at the template default")
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

func TestSystemConfigValueRoundTrip(t *testing.T) {
	if !platform.IsPrivileged() {
		t.Skip("the managed config takes root ownership, which needs an elevated process")
	}
	globalDir := t.TempDir()
	useManagedConfigDir(t, globalDir)
	orig := platform.IsPrivileged
	t.Cleanup(func() { platform.IsPrivileged = orig })

	require.NoError(t, SetSystemConfigValue("paranoid", "true"), "the file is created from the template first")
	got, err := GetSystemConfigValue("paranoid")
	require.NoError(t, err)
	assert.Equal(t, true, got)

	_, err = GetSystemConfigValue("no.such.key")
	require.Error(t, err)

	platform.IsPrivileged = func() bool { return false }
	require.Error(t, SetSystemConfigValue("paranoid", "false"), "only root may change the managed config")
	got, err = GetSystemConfigValue("paranoid")
	require.NoError(t, err)
	assert.Equal(t, true, got, "any user may read it")
}

func TestWriteAndRemoveSystemTemplateConfig(t *testing.T) {
	globalDir := t.TempDir()
	useManagedConfigDir(t, globalDir)

	require.NoError(t, WriteSystemTemplateConfig())
	assert.FileExists(t, filepath.Join(globalDir, "config.yml"))
	assert.Equal(t, globalDir, SystemConfigDir())
	assert.Equal(t, filepath.Join(globalDir, "config.yml"), globalConfigFilePath())

	require.NoError(t, WriteSystemTemplateConfig())

	require.NoError(t, RemoveSystemConfigFile())
	assert.NoFileExists(t, filepath.Join(globalDir, "config.yml"))
	require.NoError(t, RemoveSystemConfigFile())
}

func TestRequireUserScope(t *testing.T) {
	stubPrivileged := func(t *testing.T, privileged bool) {
		t.Helper()
		orig := platform.IsPrivileged
		platform.IsPrivileged = func() bool { return privileged }
		t.Cleanup(func() { platform.IsPrivileged = orig })
	}
	requireDenied := func(t *testing.T, err error) usefulerror.UsefulError {
		t.Helper()
		require.Error(t, err)
		ue, ok := usefulerror.AsUsefulError(err)
		require.True(t, ok, "%v", err)
		assert.Equal(t, errcodes.PermissionDenied, ue.Code())
		return ue
	}
	useManagedFile := func(t *testing.T) {
		t.Helper()
		globalDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte("paranoid: true\n"), 0o644))
		useManagedConfigDir(t, globalDir)
		t.Setenv("PMG_CONFIG_DIR", t.TempDir())
		initConfig()
		require.True(t, Get().IsManaged())
	}

	t.Run("a managed config names --system to root", func(t *testing.T) {
		useManagedFile(t)
		stubPrivileged(t, true)
		ue := requireDenied(t, RequireUserScope("set"))
		assert.Contains(t, ue.HumanError(), "globally managed")
		assert.Contains(t, ue.HumanError(), "`pmg config set --system`", "cobra prints the sentence, not the help")
	})

	t.Run("a managed config refuses a user", func(t *testing.T) {
		useManagedFile(t)
		stubPrivileged(t, false)
		ue := requireDenied(t, RequireUserScope("set"))
		assert.Contains(t, ue.HumanError(), "globally managed")
		assert.Contains(t, ue.HumanError(), "cannot be changed")
	})

	t.Run("sudo without a managed config refuses", func(t *testing.T) {
		useManagedConfigDir(t, t.TempDir())
		t.Setenv("PMG_CONFIG_DIR", t.TempDir())
		initConfig()
		stubPrivileged(t, true)
		t.Setenv("SUDO_USER", "alice")
		if !platform.IsSudo() {
			t.Skip("sudo cannot be faked on this platform")
		}
		ue := requireDenied(t, RequireUserScope("edit"))
		assert.Contains(t, ue.HumanError(), "`pmg config edit` would change root's per-user config")
	})

	t.Run("a plain user passes", func(t *testing.T) {
		useManagedConfigDir(t, t.TempDir())
		t.Setenv("PMG_CONFIG_DIR", t.TempDir())
		t.Setenv("SUDO_USER", "")
		initConfig()
		stubPrivileged(t, false)
		require.NoError(t, RequireUserScope("set"))
	})
}

func TestSystemConfigSetKeepsAPartialFile(t *testing.T) {
	if !platform.IsPrivileged() {
		t.Skip("the managed config takes root ownership, which needs an elevated process")
	}
	globalDir := t.TempDir()
	path := filepath.Join(globalDir, "config.yml")
	require.NoError(t, os.WriteFile(path, []byte("paranoid: true\n"), 0o644))
	useManagedConfigDir(t, globalDir)

	require.NoError(t, SetSystemConfigValue("paranoid", "false"))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "paranoid: false\n", string(data), "the other template keys stay out of the file")
}
