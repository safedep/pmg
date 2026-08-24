package alias

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfigDir(t *testing.T, home string) string {
	t.Helper()
	return filepath.Join(home, ".config", "safedep", "pmg")
}

func newTestAliasManager(t *testing.T, configDir string) *AliasManager {
	t.Helper()

	cfg := DefaultConfig()
	rcm, err := NewDefaultRcFileManager(configDir, cfg.RcFileName)
	require.NoError(t, err)

	return New(cfg, rcm)
}

func TestAliasInstallCreatesPrimaryShellRcFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	configDir := testConfigDir(t, home)
	require.NoError(t, newTestAliasManager(t, configDir).Install())

	rc := filepath.Join(configDir, RcFileName)
	assert.FileExists(t, rc)
	data, err := os.ReadFile(rc)
	require.NoError(t, err)
	assert.Contains(t, string(data), "alias npm='pmg npm'")

	assert.NoFileExists(t, filepath.Join(home, LegacyRcFileName))

	zshrc := filepath.Join(home, ".zshrc")
	assert.FileExists(t, zshrc)
	zdata, err := os.ReadFile(zshrc)
	require.NoError(t, err)
	assert.Contains(t, string(zdata), rc)

	// Shells the user does not use are left untouched.
	assert.NoFileExists(t, filepath.Join(home, ".bashrc"))
	assert.NoFileExists(t, filepath.Join(home, ".config", "fish", "config.fish"))
}

func TestAliasInstallKeepsLegacyRcFileInPlace(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	legacy := filepath.Join(home, LegacyRcFileName)
	require.NoError(t, os.WriteFile(legacy, []byte("# existing install\n"), 0o644))

	configDir := testConfigDir(t, home)
	require.NoError(t, newTestAliasManager(t, configDir).Install())

	data, err := os.ReadFile(legacy)
	require.NoError(t, err)
	assert.Contains(t, string(data), "alias npm='pmg npm'")
	assert.NoFileExists(t, filepath.Join(configDir, RcFileName))
}

func TestAliasRemoveClearsLegacyThenInstallUsesConfigDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	legacy := filepath.Join(home, LegacyRcFileName)
	require.NoError(t, os.WriteFile(legacy, []byte("# existing install\n"), 0o644))

	configDir := testConfigDir(t, home)
	require.NoError(t, newTestAliasManager(t, configDir).Remove())
	assert.NoFileExists(t, legacy)

	require.NoError(t, newTestAliasManager(t, configDir).Install())
	assert.FileExists(t, filepath.Join(configDir, RcFileName))
	assert.NoFileExists(t, legacy)
}

func TestAliasInstallWiresExistingNonPrimaryShell(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	require.NoError(t, os.WriteFile(filepath.Join(home, ".bashrc"), []byte("# bashrc\n"), 0o644))

	require.NoError(t, newTestAliasManager(t, testConfigDir(t, home)).Install())

	bashrc, err := os.ReadFile(filepath.Join(home, ".bashrc"))
	require.NoError(t, err)
	assert.Contains(t, string(bashrc), RcFileName)

	zshrc, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	require.NoError(t, err)
	assert.Contains(t, string(zshrc), RcFileName)
}

func TestAliasInstallIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	mgr := newTestAliasManager(t, testConfigDir(t, home))
	require.NoError(t, mgr.Install())
	require.NoError(t, mgr.Install())

	data, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	require.NoError(t, err)

	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, RcFileName) {
			count++
		}
	}
	assert.Equal(t, 1, count, "source line should appear exactly once")
}

func TestAliasRemove(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	configDir := testConfigDir(t, home)
	mgr := newTestAliasManager(t, configDir)
	require.NoError(t, mgr.Install())
	require.NoError(t, mgr.Remove())

	assert.NoFileExists(t, filepath.Join(configDir, RcFileName))
	assert.NoFileExists(t, filepath.Join(home, LegacyRcFileName))

	data, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	require.NoError(t, err)
	assert.NotContains(t, string(data), RcFileName)
}

func TestAliasDetectionIgnoresUnrelatedRcPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	// A user-managed file whose name merely ends in the pmg rc file name must
	// not read as a pmg install, and must survive removal.
	unrelated := "[ -f '" + filepath.Join(home, "my-pmg.rc") + "' ] && source '" + filepath.Join(home, "my-pmg.rc") + "'\n"
	zshrc := filepath.Join(home, ".zshrc")
	require.NoError(t, os.WriteFile(zshrc, []byte(unrelated), 0o644))

	mgr := newTestAliasManager(t, testConfigDir(t, home))

	installed, err := mgr.IsInstalled()
	require.NoError(t, err)
	assert.False(t, installed)

	require.NoError(t, mgr.Install())
	require.NoError(t, mgr.Remove())

	data, err := os.ReadFile(zshrc)
	require.NoError(t, err)
	assert.Contains(t, string(data), "my-pmg.rc")
	assert.NotContains(t, string(data), aliasSourceMarker)
}

func TestAliasInstallReplacesStaleSourceLine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	// An install from the legacy layout, whose rc file the user then deleted
	// while leaving .zshrc alone.
	legacy := filepath.Join(home, LegacyRcFileName)
	zshrc := filepath.Join(home, ".zshrc")
	staleShell, err := NewZshShell()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(zshrc, []byte(staleShell.Source(legacy)), 0o644))

	configDir := testConfigDir(t, home)
	require.NoError(t, newTestAliasManager(t, configDir).Install())

	rcPath := filepath.Join(configDir, RcFileName)
	assert.FileExists(t, rcPath)

	data, err := os.ReadFile(zshrc)
	require.NoError(t, err)
	assert.Contains(t, string(data), rcPath)
	assert.NotContains(t, string(data), legacy, "the stale source line must not survive")
	assert.Equal(t, 1, strings.Count(string(data), aliasSourceMarker))
}
