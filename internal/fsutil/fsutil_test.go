package fsutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathWithinDir(t *testing.T) {
	assert.True(t, PathWithinDir("/usr/local/lib/pmg/bin", "/usr/local/lib/pmg/bin"))
	assert.True(t, PathWithinDir("/usr/local/lib/pmg/bin/npm", "/usr/local/lib/pmg/bin"))
	assert.False(t, PathWithinDir("/usr/local/bin/npm", "/usr/local/lib/pmg/bin"))
	assert.False(t, PathWithinDir("/usr/local/lib/pmg/bin-extra/npm", "/usr/local/lib/pmg/bin"))
	assert.False(t, PathWithinDir("/usr/local/bin/npm", ""))
	assert.False(t, PathWithinDir("", "/usr/local/bin"))
}

func TestMkdirAllRootOwnedCreatesMissingChain(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "a", "b", "c")

	require.NoError(t, MkdirAllRootOwned(target, 0o755))

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	require.NoError(t, MkdirAllRootOwned(target, 0o755), "idempotent on existing dir")
}

func TestMkdirAllRootOwnedRejectsFileCollision(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o644))

	assert.Error(t, MkdirAllRootOwned(blocker, 0o755))
	assert.Error(t, MkdirAllRootOwned(filepath.Join(blocker, "sub"), 0o755))
}

func TestMkdirAllRootOwnedLeavesExistingDirsAlone(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing")
	require.NoError(t, os.Mkdir(existing, 0o700))

	require.NoError(t, MkdirAllRootOwned(filepath.Join(existing, "created"), 0o755))

	info, err := os.Stat(existing)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
		"pre-existing directory permissions must not be changed")
}
