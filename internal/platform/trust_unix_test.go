//go:build unix

package platform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMkdirAllRootOwnedCreatesMissingChain(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "a", "b", "c")

	require.NoError(t, mkdirAllRootOwned(target, 0o755))

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	require.NoError(t, mkdirAllRootOwned(target, 0o755), "idempotent on existing dir")
}

func TestMkdirAllRootOwnedRejectsFileCollision(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o644))

	assert.Error(t, mkdirAllRootOwned(blocker, 0o755))
	assert.Error(t, mkdirAllRootOwned(filepath.Join(blocker, "sub"), 0o755))
}

func TestMkdirAllRootOwnedLeavesExistingDirsAlone(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing")
	require.NoError(t, os.Mkdir(existing, 0o700))

	require.NoError(t, mkdirAllRootOwned(filepath.Join(existing, "created"), 0o755))

	info, err := os.Stat(existing)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
		"pre-existing directory permissions must not be changed")
}

func TestProtectSystemPathIsANoOpWithoutPrivilege(t *testing.T) {
	withPrivilege(t, false)
	file := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(file, []byte("paranoid: false\n"), 0o600))

	require.NoError(t, ProtectSystemPath(file, 0o644))

	info, err := os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestRequireNotReparsePointRejectsASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o755))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))

	assert.NoError(t, RequireNotReparsePoint(target))
	assert.NoError(t, RequireNotReparsePoint(filepath.Join(dir, "missing")))
	assert.ErrorContains(t, RequireNotReparsePoint(link), "is a link")
}
