//go:build !windows

package cloudauth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Windows has no Unix mode bits and no uid, so these checks apply on Unix
// only.
func TestCredentialFileUnixAccess(t *testing.T) {
	t.Run("write gives the file mode 0600", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, WriteCredentialFile(path, testCredential))
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})

	t.Run("read refuses a file that other users can read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, WriteCredentialFile(path, testCredential))
		require.NoError(t, os.Chmod(path, 0o644))
		_, err := ReadCredentialFile(path)
		assert.ErrorContains(t, err, "other users must have no access")
	})

	t.Run("read refuses a file of another user", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("only root can give a file to another user")
		}
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, WriteCredentialFile(path, testCredential))
		require.NoError(t, os.Chown(path, 65534, 65534))
		_, err := ReadCredentialFile(path)
		assert.ErrorContains(t, err, "belongs to uid 65534")
	})
}
