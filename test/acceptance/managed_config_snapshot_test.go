//go:build acceptance

package acceptance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagedConfigSnapshotRestoresContentsAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(path, []byte("paranoid: true\n"), 0o640))
	// Windows keeps only a read-only bit, so compare with the mode the file
	// had, not with 0o640.
	orig, err := os.Stat(path)
	require.NoError(t, err)

	s, err := saveManagedConfig(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("paranoid: false\n"), 0o644))
	s.restore()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "paranoid: true\n", string(data))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, orig.Mode().Perm(), info.Mode().Perm())
}

func TestManagedConfigSnapshotRemovesAFileAScriptCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")

	s, err := saveManagedConfig(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("global_lockdown: true\n"), 0o644))
	s.restore()
	assert.NoFileExists(t, path)

	empty, err := saveManagedConfig("")
	require.NoError(t, err)
	empty.restore()
}

func TestManagedConfigSnapshotFailsWhenTheFileCannotBeRead(t *testing.T) {
	dir := t.TempDir()
	_, err := saveManagedConfig(dir)
	require.Error(t, err, "a path that exists but is not readable as a file must not count as absent")
	assert.DirExists(t, dir)
}
