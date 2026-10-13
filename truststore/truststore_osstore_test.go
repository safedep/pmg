//go:build darwin || windows

package truststore

import (
	"testing"

	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/stretchr/testify/require"
)

// persistedCA writes a new PMG CA to a temporary config directory, as
// `pmg setup cert install` does, and returns the directory and the CA.
func persistedCA(t *testing.T) (string, *certmanager.Certificate) {
	t.Helper()
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.DefaultCertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))
	return dir, ca
}
