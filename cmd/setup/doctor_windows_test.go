//go:build windows

package setup

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/internal/shim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookInDirs(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(second, "npm.cmd"), nil, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(second, "pip.exe"), nil, 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(first, "uv.exe"), 0o755))
	exts := []string{".COM", ".EXE", ".BAT", ".CMD"}

	t.Run("applies PATHEXT in order across directories", func(t *testing.T) {
		got, err := lookInDirs("npm", []string{first, second}, exts)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(second, "npm.cmd"), got)

		got, err = lookInDirs("pip", []string{first, second}, exts)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(second, "pip.exe"), got)
	})

	t.Run("skips a directory that carries the name", func(t *testing.T) {
		_, err := lookInDirs("uv", []string{first, second}, exts)
		assert.ErrorIs(t, err, exec.ErrNotFound)
	})

	t.Run("reports a missing name like LookPath", func(t *testing.T) {
		_, err := lookInDirs("yarn", []string{first, second}, exts)
		var execErr *exec.Error
		require.ErrorAs(t, err, &execErr)
		assert.Equal(t, "yarn", execErr.Name)
	})
}

func TestCheckShimDirectoryFiles(t *testing.T) {
	pmgBin, err := os.Executable()
	require.NoError(t, err)
	managers := alias.DefaultConfig().PackageManagers

	writeShims := func(t *testing.T, dir, bin string) {
		t.Helper()
		mgr := shim.NewShimManager(shim.ShimConfig{
			BinDir:          dir,
			PMGBin:          bin,
			PackageManagers: managers,
			SkipUserPath:    true,
		})
		require.NoError(t, mgr.Install())
	}

	t.Run("every shim names this pmg.exe", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin)

		result := checkShimDirectoryFiles(dir)
		assert.Equal(t, doctor.StatusPass, result.Status)
	})

	t.Run("a shim from an older install names another binary", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin)
		stale := shim.NewShimManager(shim.ShimConfig{
			BinDir:          dir,
			PMGBin:          `C:\old\pmg.exe`,
			PackageManagers: []string{"npm"},
			SkipUserPath:    true,
		})
		require.NoError(t, stale.Install())

		result := checkShimDirectoryFiles(dir)
		assert.Equal(t, doctor.StatusFail, result.Status)
		assert.Equal(t, "Shims for npm name another pmg.exe", result.Message)
	})

	t.Run("a missing shim is named", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin)
		require.NoError(t, os.Remove(filepath.Join(dir, shim.ShimFileName("pip"))))

		result := checkShimDirectoryFiles(dir)
		assert.Equal(t, doctor.StatusFail, result.Status)
		assert.Equal(t, "Shims missing for pip", result.Message)
	})

	t.Run("an empty directory reads as not found", func(t *testing.T) {
		result := checkShimDirectoryFiles(t.TempDir())
		assert.Equal(t, doctor.StatusFail, result.Status)
		assert.Equal(t, "Shim directory not found", result.Message)
	})
}

// The install warning and the doctor Fix column print the same lines from
// the same resolutions, so they cannot disagree on a path. Neither tells the
// user to reorder PATH, which cannot put a user entry ahead of a machine
// entry.
func TestShadowedFixAndWarningShareTheResolvedPath(t *testing.T) {
	shadowed := []managerResolution{
		{Name: "npm", Path: `C:\Program Files\nodejs\npm.cmd`},
		{Name: "npx", Path: `C:\Program Files\nodejs\npx.cmd`},
	}

	lines := shadowedLines(shadowed)
	fix := shadowedFix(shadowed)

	assert.Equal(t, []string{
		`npm is C:\Program Files\nodejs\npm.cmd.`,
		`npx is C:\Program Files\nodejs\npx.cmd.`,
	}, lines)
	for _, line := range lines {
		assert.Contains(t, fix, line)
	}
	assert.Contains(t, fix, "Run them as `pmg <manager>`")
	assert.NotContains(t, fix, "Move")
}
