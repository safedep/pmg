package certmanager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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

func TestLoadUsableCA(t *testing.T) {
	tests := []struct {
		name    string
		save    func(t *testing.T, dir string)
		wantErr error
	}{
		{
			name: "valid CA",
			save: func(t *testing.T, dir string) {
				ca, err := GenerateCA(DefaultCertManagerConfig())
				require.NoError(t, err)
				require.NoError(t, SaveCA(dir, ca))
			},
		},
		{
			name:    "CA that expires within an hour",
			save:    func(t *testing.T, dir string) { require.NoError(t, SaveCA(dir, caExpiringIn(t, 30*time.Minute))) },
			wantErr: ErrCAExpired,
		},
		{
			name:    "missing CA",
			save:    func(*testing.T, string) {},
			wantErr: os.ErrNotExist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.save(t, dir)

			ca, err := LoadUsableCA(dir)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, ca)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, ca.X509Cert)
		})
	}
}

func caExpiringIn(t *testing.T, validity time.Duration) *Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: CACommonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return &Certificate{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	}
}
