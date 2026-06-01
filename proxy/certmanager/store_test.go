package certmanager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestLoadOrCreatePersistedCA_RegeneratesExpiredCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := ProxyCAPaths(dir)

	expired := generateTestCA(t, time.Now().Add(-2*time.Hour))
	require.NoError(t, os.WriteFile(certPath, expired.Certificate, 0o600))
	require.NoError(t, os.WriteFile(keyPath, expired.PrivateKey, 0o600))

	ca, err := LoadOrCreatePersistedCA(dir)
	require.NoError(t, err)
	require.NotNil(t, ca)

	assert.False(t, ca.IsExpired(certExpiryThreshold))
	assert.NotEqual(t, string(expired.Certificate), string(ca.Certificate))

	reloaded, err := LoadOrCreatePersistedCA(dir)
	require.NoError(t, err)
	assert.Equal(t, string(ca.Certificate), string(reloaded.Certificate))
}

func TestWriteProxyCABundle_SkipsFreshBundle(t *testing.T) {
	dir := t.TempDir()

	ca, err := LoadOrCreatePersistedCA(dir)
	require.NoError(t, err)

	certPath, _, bundlePath := ProxyCAPaths(dir)
	require.NoError(t, os.WriteFile(bundlePath, []byte("existing bundle\n"), 0o600))

	certTime := time.Now().Add(-2 * time.Hour)
	bundleTime := time.Now().Add(-1 * time.Hour)
	require.NoError(t, os.Chtimes(certPath, certTime, certTime))
	require.NoError(t, os.Chtimes(bundlePath, bundleTime, bundleTime))

	writtenPath, err := WriteProxyCABundle(dir, ca)
	require.NoError(t, err)
	assert.Equal(t, bundlePath, writtenPath)

	bundle, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, "existing bundle\n", string(bundle))
}

func generateTestCA(t *testing.T, notAfter time.Time) *Certificate {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, DefaultCertManagerConfig().KeySize)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   ProxyCACommonName,
			Organization: []string{"SafeDep PMG"},
		},
		NotBefore:             notAfter.Add(-24 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	x509Cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	return &Certificate{
		Certificate: certPEM,
		PrivateKey:  keyPEM,
		X509Cert:    x509Cert,
		PrivKey:     privKey,
	}
}
