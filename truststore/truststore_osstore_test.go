//go:build darwin || windows

package truststore

import (
	"crypto/sha1"
	"fmt"
	"slices"
	"testing"

	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/stretchr/testify/assert"
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

func TestStatusCountsOnlyTheExactCA(t *testing.T) {
	dir, ca := persistedCA(t)
	thumbprint := fmt.Sprintf("%X", sha1.Sum(ca.X509Cert.Raw))
	tests := []struct {
		name         string
		exactTrusted bool
	}{
		{name: "the stores hold another certificate with the same name"},
		{name: "the OS trusts the persisted CA", exactTrusted: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := commandRunner
			commandRunner = func(_ string, args ...string) ([]byte, error) {
				exactCheck := slices.Contains(args, "verify-cert") || slices.Contains(args, thumbprint)
				if exactCheck && !tt.exactTrusted {
					return nil, assert.AnError
				}
				return nil, nil
			}
			t.Cleanup(func() { commandRunner = orig })

			user, system, err := Status(dir)
			require.NoError(t, err)
			assert.Equal(t, tt.exactTrusted, user)
			assert.Equal(t, tt.exactTrusted, system)
		})
	}
}
