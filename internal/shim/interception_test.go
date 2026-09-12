package shim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterceptionInspectionPartition(t *testing.T) {
	underShimResolution := ManagerResolution{Name: "npm", UnderShim: true}
	shadowedResolution := ManagerResolution{Name: "pip"}
	inspection := InterceptionInspection{Resolutions: []ManagerResolution{underShimResolution, shadowedResolution}}

	underShim, shadowed := inspection.Partition()

	assert.Equal(t, []ManagerResolution{underShimResolution}, underShim)
	assert.Equal(t, []ManagerResolution{shadowedResolution}, shadowed)
}

func TestPathUnderAnyDir(t *testing.T) {
	systemDir := filepath.Join("/", "usr", "local", "lib", "pmg", "bin")
	userDir := filepath.Join("/", "home", "dev", ".pmg", "bin")
	dirs := []string{systemDir, userDir}

	assert.True(t, PathUnderAnyDir(filepath.Join(systemDir, "npm"), dirs))
	assert.True(t, PathUnderAnyDir(filepath.Join(userDir, "pip"), dirs))
	assert.False(t, PathUnderAnyDir(filepath.Join("/", "usr", "bin", "yarn"), dirs))
}

// A shim names the pmg binary by absolute path at install time and nothing
// updates it later. A second install, a moved binary, or a package upgrade
// into a versioned directory leaves the shim naming another binary.
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

	t.Run("every shim names this binary", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin, managers)

		inspection, err := InspectShimFiles(dir, managers)
		require.NoError(t, err)
		assert.Empty(t, inspection.Missing)
		assert.Empty(t, inspection.BinaryMissing)
		assert.Empty(t, inspection.BinaryDiffers)
	})

	t.Run("a shim naming another binary that runs", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin, managers)

		other := filepath.Join(t.TempDir(), "pmg")
		require.NoError(t, os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755))
		writeShims(t, dir, other, []string{"npm"})

		inspection, err := InspectShimFiles(dir, managers)
		require.NoError(t, err)
		assert.Equal(t, []string{"npm"}, inspection.BinaryDiffers)
		assert.Empty(t, inspection.BinaryMissing)
		assert.Empty(t, inspection.Missing)
	})

	t.Run("a shim naming a binary that is gone", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin, managers)
		writeShims(t, dir, filepath.Join(t.TempDir(), "removed", "pmg"), []string{"npm"})

		inspection, err := InspectShimFiles(dir, managers)
		require.NoError(t, err)
		assert.Equal(t, []string{"npm"}, inspection.BinaryMissing)
		assert.Empty(t, inspection.BinaryDiffers)
	})

	t.Run("a missing shim file", func(t *testing.T) {
		dir := t.TempDir()
		writeShims(t, dir, pmgBin, []string{"npm"})

		inspection, err := InspectShimFiles(dir, managers)
		require.NoError(t, err)
		assert.Equal(t, []string{"pip"}, inspection.Missing)
	})

	t.Run("a file that is not a pmg shim reads as missing", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, shimFileName("npm")), []byte("not a shim\n"), 0o755))

		inspection, err := InspectShimFiles(dir, []string{"npm"})
		require.NoError(t, err)
		assert.Equal(t, []string{"npm"}, inspection.Missing)
	})

	t.Run("an empty directory", func(t *testing.T) {
		inspection, err := InspectShimFiles(t.TempDir(), managers)
		require.NoError(t, err)
		assert.Equal(t, managers, inspection.Missing)
	})
}
