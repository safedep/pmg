//go:build unix

package fsutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Windows has no Unix permission bits to preserve.
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
