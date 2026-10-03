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

	s := saveManagedConfig(path)
	require.NoError(t, os.WriteFile(path, []byte("paranoid: false\n"), 0o644))
	s.restore()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "paranoid: true\n", string(data))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestManagedConfigSnapshotRemovesAFileAScriptCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")

	s := saveManagedConfig(path)
	require.NoError(t, os.WriteFile(path, []byte("global_lockdown: true\n"), 0o644))
	s.restore()
	assert.NoFileExists(t, path)

	saveManagedConfig("").restore()
}
