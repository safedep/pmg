package alias

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAliasManager(t *testing.T) *AliasManager {
	t.Helper()

	cfg := DefaultConfig()
	rcm, err := NewDefaultRcFileManager(cfg.RcFileName)
	require.NoError(t, err)

	return New(cfg, rcm)
}

func TestAliasInstallCreatesPrimaryShellRcFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	require.NoError(t, newTestAliasManager(t).Install())

	rc := filepath.Join(home, ".pmg.rc")
	assert.FileExists(t, rc)
	data, err := os.ReadFile(rc)
	require.NoError(t, err)
	assert.Contains(t, string(data), "alias npm='pmg npm'")

	zshrc := filepath.Join(home, ".zshrc")
	assert.FileExists(t, zshrc)
	zdata, err := os.ReadFile(zshrc)
	require.NoError(t, err)
	assert.Contains(t, string(zdata), ".pmg.rc")

	// Shells the user does not use are left untouched.
	assert.NoFileExists(t, filepath.Join(home, ".bashrc"))
	assert.NoFileExists(t, filepath.Join(home, ".config", "fish", "config.fish"))
}

func TestAliasInstallWiresExistingNonPrimaryShell(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	require.NoError(t, os.WriteFile(filepath.Join(home, ".bashrc"), []byte("# bashrc\n"), 0o644))

	require.NoError(t, newTestAliasManager(t).Install())

	bashrc, err := os.ReadFile(filepath.Join(home, ".bashrc"))
	require.NoError(t, err)
	assert.Contains(t, string(bashrc), ".pmg.rc")

	zshrc, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	require.NoError(t, err)
	assert.Contains(t, string(zshrc), ".pmg.rc")
}

func TestAliasInstallIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	mgr := newTestAliasManager(t)
	require.NoError(t, mgr.Install())
	require.NoError(t, mgr.Install())

	data, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	require.NoError(t, err)

	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, ".pmg.rc") {
			count++
		}
	}
	assert.Equal(t, 1, count, "source line should appear exactly once")
}

func TestAliasRemove(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")

	mgr := newTestAliasManager(t)
	require.NoError(t, mgr.Install())
	require.NoError(t, mgr.Remove())

	assert.NoFileExists(t, filepath.Join(home, ".pmg.rc"))

	data, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	require.NoError(t, err)
	assert.NotContains(t, string(data), ".pmg.rc")
}
