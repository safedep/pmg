package certmanager

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndLoadCARoundTrip(t *testing.T) {
	dir := t.TempDir()

	ca, err := GenerateCA(DefaultCertManagerConfig())
	require.NoError(t, err)

	require.NoError(t, SaveCA(dir, ca))

	if runtime.GOOS != "windows" {
		keyInfo, err := os.Stat(CAKeyPath(dir))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())

		certInfo, err := os.Stat(CACertPath(dir))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), certInfo.Mode().Perm())
	}

	loaded, err := LoadCA(dir)
	require.NoError(t, err)
	assert.Equal(t, ca.Certificate, loaded.Certificate)
	assert.Equal(t, ca.PrivateKey, loaded.PrivateKey)
	require.NotNil(t, loaded.X509Cert)
	require.NotNil(t, loaded.PrivKey)
}

func TestLoadCAMissingIsNotExist(t *testing.T) {
	_, err := LoadCA(filepath.Join(t.TempDir(), "nope"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

func TestPersistentConfigIsLongLived(t *testing.T) {
	assert.Equal(t, 3650, PersistentCACertManagerConfig().CAValidityDays)
}
