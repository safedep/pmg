package certmanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadOrCreatePersistedCA_CreatesAndReloadsSameCert(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreatePersistedCA(dir)
	require.NoError(t, err)
	require.NotNil(t, first)

	certPath, keyPath, bundlePath := ProxyCAPaths(dir)
	assert.FileExists(t, certPath)
	assert.FileExists(t, keyPath)

	second, err := LoadOrCreatePersistedCA(dir)
	require.NoError(t, err)
	assert.Equal(t, string(first.Certificate), string(second.Certificate))
	assert.Equal(t, string(first.PrivateKey), string(second.PrivateKey))

	bundlePathWritten, err := WriteProxyCABundle(dir, second)
	require.NoError(t, err)
	assert.Equal(t, bundlePath, bundlePathWritten)
	assert.FileExists(t, bundlePath)

	require.NoError(t, RemovePersistedCA(dir))
	for _, path := range []string{certPath, keyPath, bundlePath} {
		_, err := os.Stat(path)
		assert.True(t, os.IsNotExist(err), "expected %s to be removed", path)
	}
}

func TestProxyCAPaths(t *testing.T) {
	certPath, keyPath, bundlePath := ProxyCAPaths(filepath.Join("cfg", "pmg"))
	assert.Equal(t, filepath.Join("cfg", "pmg", proxyCACertFilename), certPath)
	assert.Equal(t, filepath.Join("cfg", "pmg", proxyCAKeyFilename), keyPath)
	assert.Equal(t, filepath.Join("cfg", "pmg", proxyCABundleFilename), bundlePath)
}
