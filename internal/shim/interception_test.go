package shim

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectInterceptionResolvesEachManagerOnce(t *testing.T) {
	shimDir := filepath.Join("/", "shims")
	calls := map[string]int{}
	lookPath := func(name string) (string, error) {
		calls[name]++
		switch name {
		case "npm":
			return filepath.Join(shimDir, "npm"), nil
		case "pip":
			return filepath.Join("/", "usr", "bin", "pip"), nil
		default:
			return "", exec.ErrNotFound
		}
	}

	inspection := inspectInterception([]string{"npm", "pip", "uv"}, []string{shimDir}, []string{"/usr/bin", shimDir}, lookPath)

	assert.Equal(t, []string{"/usr/bin", shimDir}, inspection.PathEntries)
	assert.Equal(t, []ManagerResolution{
		{Name: "npm", Path: filepath.Join(shimDir, "npm"), UnderShim: true},
		{Name: "pip", Path: filepath.Join("/", "usr", "bin", "pip")},
	}, inspection.Resolutions, "configured order kept, unresolved manager omitted")
	assert.Equal(t, map[string]int{"npm": 1, "pip": 1, "uv": 1}, calls)

	underShim, shadowed := inspection.Partition()
	assert.Equal(t, []ManagerResolution{inspection.Resolutions[0]}, underShim)
	assert.Equal(t, []ManagerResolution{inspection.Resolutions[1]}, shadowed)
}

func TestPathUnderAnyDir(t *testing.T) {
	systemDir := filepath.Join("/", "usr", "local", "lib", "pmg", "bin")
	userDir := filepath.Join("/", "home", "dev", ".pmg", "bin")
	dirs := []string{systemDir, userDir}

	assert.True(t, PathUnderAnyDir(filepath.Join(systemDir, "npm"), dirs))
	assert.True(t, PathUnderAnyDir(filepath.Join(userDir, "pip"), dirs))
	assert.False(t, PathUnderAnyDir(filepath.Join("/", "usr", "bin", "yarn"), dirs))
}

func TestInspectShimFiles(t *testing.T) {
	pmgBin, err := os.Executable()
	require.NoError(t, err)
	managers := []string{"npm", "pip"}

	writeShims := func(t *testing.T, dir, bin string, pms []string) {
		t.Helper()
		require.NoError(t, NewShimManager(ShimConfig{
			BinDir:          dir,
			PMGBin:          bin,
			PackageManagers: pms,
			SkipUserPath:    true,
		}).Install())
	}

	t.Run("valid", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin, managers)

		inspection, err := InspectShimFiles(dir, managers, pmgBin)
		require.NoError(t, err)
		assert.Empty(t, inspection.Missing)
		assert.Empty(t, inspection.Stale)
	})

	t.Run("stale", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin, managers)
		writeShims(t, dir, filepath.Join(t.TempDir(), "old", "pmg"), []string{"npm"})

		inspection, err := InspectShimFiles(dir, managers, pmgBin)
		require.NoError(t, err)
		assert.Equal(t, []string{"npm"}, inspection.Stale)
		assert.Empty(t, inspection.Missing)
	})

	t.Run("missing", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin, []string{"npm"})

		inspection, err := InspectShimFiles(dir, managers, pmgBin)
		require.NoError(t, err)
		assert.Equal(t, []string{"pip"}, inspection.Missing)
		assert.Empty(t, inspection.Stale)
	})

	t.Run("empty directory", func(t *testing.T) {
		inspection, err := InspectShimFiles(t.TempDir(), managers, pmgBin)
		require.NoError(t, err)
		assert.Equal(t, managers, inspection.Missing)
	})
}
