//go:build unix

package shim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/alias"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sh body, the executable bit and the rc-file PATH export are the Unix
// half of the shim.
func TestShimManagerInstall(t *testing.T) {
	homeDir := t.TempDir()
	binDir := filepath.Join(homeDir, ".pmg", "bin")

	bashrc := filepath.Join(homeDir, ".bashrc")
	zshrc := filepath.Join(homeDir, ".zshrc")
	fishConfig := filepath.Join(homeDir, ".config", "fish")
	require.NoError(t, os.MkdirAll(fishConfig, 0o755))
	require.NoError(t, os.WriteFile(bashrc, []byte("# existing bashrc\n"), 0o644))
	require.NoError(t, os.WriteFile(zshrc, []byte("# existing zshrc\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(fishConfig, "config.fish"), []byte("# existing fish config\n"), 0o644))

	pms := []string{"npm", "pip"}
	pmgBin := filepath.Join(homeDir, "bin", "pmg")
	shells := []alias.Shell{
		&stubShell{name: "bash", path: ".bashrc", useFish: false},
		&stubShell{name: "fish", path: ".config/fish/config.fish", useFish: true},
	}

	mgr := NewShimManager(ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
		PMGBin:          pmgBin,
		PackageManagers: pms,
		Shells:          shells,
	})

	require.NoError(t, mgr.Install())

	for _, pm := range pms {
		shimPath := filepath.Join(binDir, pm)
		info, err := os.Stat(shimPath)
		require.NoError(t, err, "shim %s should exist", pm)
		assert.NotZero(t, info.Mode()&0o111, "shim %s should be executable", pm)

		content, err := os.ReadFile(shimPath)
		require.NoError(t, err)
		assert.Contains(t, string(content), "#!/bin/sh")
		assert.Contains(t, string(content), "PMG_BIN='"+pmgBin+"'")
		assert.Contains(t, string(content), `exec "$PMG_BIN" `+pm+` "$@"`)
		assert.Contains(t, string(content), `PMG_SHIM_PATH=$(cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")`)
		assert.Contains(t, string(content), "export PMG_SHIM_PATH")
		assert.NotContains(t, string(content), "command -v pmg")
		assert.NotContains(t, string(content), "exec pmg")
		assert.NotContains(t, string(content), "falling back to native")
	}

	bashContent, err := os.ReadFile(bashrc)
	require.NoError(t, err)
	assert.Contains(t, string(bashContent), binDir)

	fishContent, err := os.ReadFile(filepath.Join(fishConfig, "config.fish"))
	require.NoError(t, err)
	assert.Contains(t, string(fishContent), binDir)
}

// os.RemoveAll under a file parent returns nil on Windows, so this only
// proves the error path on Unix.
func TestShimManagerRemoveReturnsDirectoryError(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0o644))

	mgr := NewShimManager(ShimConfig{
		BinDir: filepath.Join(blocker, "bin"),
	})

	assert.Error(t, mgr.Remove())
}

// The shim body single-quotes a POSIX path. A Windows shim has a different
// body and its own test.
func TestShimManagerInstallEscapesPMGBin(t *testing.T) {
	homeDir := t.TempDir()
	binDir := filepath.Join(homeDir, ".pmg", "bin")
	pmgBin := filepath.Join(homeDir, "PMG's bin", "pmg")

	mgr := NewShimManager(ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
		PMGBin:          pmgBin,
		PackageManagers: []string{"npm"},
	})

	require.NoError(t, mgr.Install())

	content, err := os.ReadFile(filepath.Join(binDir, "npm"))
	require.NoError(t, err)
	assert.Contains(t, string(content), `PMG_BIN='`+homeDir+`/PMG'\''s bin/pmg'`)
	assert.NotContains(t, string(content), "command -v pmg")
}
