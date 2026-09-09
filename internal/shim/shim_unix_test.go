//go:build unix

package shim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
