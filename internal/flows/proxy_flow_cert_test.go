package flows

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPersistedCAAbsent(t *testing.T) {
	_, ok := loadPersistedCA(t.TempDir())
	assert.False(t, ok)
}

func TestLoadPersistedCAPresent(t *testing.T) {
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))

	loaded, ok := loadPersistedCA(dir)
	require.True(t, ok)
	assert.Equal(t, ca.Certificate, loaded.Certificate)
}

// TestSetupCACertificateWritesMergedTempFile verifies that setupCACertificate
// creates a temp file containing the pure CA as a prefix of the merged bundle.
// config.Get() is safe to call without setup — it is initialised via package init.
func TestSetupCACertificateWritesMergedTempFile(t *testing.T) {
	f := &proxyFlow{}
	caCert, path, err := f.setupCACertificate()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(path) })

	require.NotNil(t, caCert)
	assert.FileExists(t, path)

	merged, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, caCert.Certificate, merged[:len(caCert.Certificate)])
}

func TestSetupCACertificateCreatesMissingOutputDir(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	outputPath := filepath.Join(configDir, "proxy-ca.pem")

	caCert, ephemeral, err := SetupCACertificate(configDir, outputPath)
	require.NoError(t, err)

	require.NotNil(t, caCert)
	assert.True(t, ephemeral)
	assert.FileExists(t, outputPath)
}
