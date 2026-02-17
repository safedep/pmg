package certmanager

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateCA(t *testing.T) {
	config := DefaultCertManagerConfig()

	ca, err := GenerateCA(config)
	assert.NoError(t, err, "Failed to generate CA")

	assert.NotNil(t, ca, "CA certificate should not be nil")

	assert.NotNil(t, ca.Certificate, "CA certificate should not be nil")
	assert.NotEmpty(t, ca.Certificate, "CA certificate should not be empty")

	assert.NotNil(t, ca.PrivateKey, "CA private key should not be nil")
	assert.NotEmpty(t, ca.PrivateKey, "CA private key should not be empty")

	assert.NotNil(t, ca.X509Cert, "Parsed X509 certificate should not be nil")

	assert.NotNil(t, ca.PrivKey, "Parsed private key should not be nil")

	assert.True(t, ca.X509Cert.IsCA, "Certificate should be marked as CA")

	assert.Equal(t, "PMG Proxy CA", ca.X509Cert.Subject.CommonName, "Common name should be PMG Proxy CA")

	assert.Greater(t, ca.X509Cert.NotAfter.Sub(ca.X509Cert.NotBefore).Hours(),
		float64(config.CAValidityDays*24-1), "CA certificate validity period should be greater than the configured validity days")
}

func TestInMemoryCache(t *testing.T) {
	cache := NewInMemoryCache()

	assert.Equal(t, 0, cache.Size(), "New cache should be empty")

	cert := &Certificate{
		Certificate: []byte("test cert"),
		PrivateKey:  []byte("test key"),
	}

	cache.Set("example.com", cert)

	assert.Equal(t, 1, cache.Size(), "Cache size should be 1")

	retrieved, found := cache.Get("example.com")
	assert.True(t, found, "Certificate should be found in cache")
	assert.Equal(t, "test cert", string(retrieved.Certificate), "Retrieved certificate should match")

	_, found = cache.Get("nonexistent.com")
	assert.False(t, found, "Non-existent certificate should not be found")

	cache.Clear()
	assert.Equal(t, 0, cache.Size(), "Cache should be empty after Clear")
}

func TestNewCertificateManagerWithCA(t *testing.T) {
	config := DefaultCertManagerConfig()
	ca, err := GenerateCA(config)
	assert.NoError(t, err, "Failed to generate CA")

	cm, err := NewCertificateManagerWithCA(ca, config)
	assert.NoError(t, err, "Failed to create certificate manager")

	assert.NotNil(t, cm, "Certificate manager should not be nil")

	retrievedCA, err := cm.GetCA()
	assert.NoError(t, err, "Failed to get CA")

	assert.Equal(t, ca, retrievedCA, "Retrieved CA should match original")
}

func TestGenerateCertForHost(t *testing.T) {
	config := DefaultCertManagerConfig()
	ca, err := GenerateCA(config)
	assert.NoError(t, err, "Failed to generate CA")

	cm, err := NewCertificateManagerWithCA(ca, config)
	assert.NoError(t, err, "Failed to create certificate manager")

	hostname := "registry.npmjs.org"

	cert, err := cm.GenerateCertForHost(hostname)
	assert.NoError(t, err, "Failed to generate host certificate")

	assert.NotNil(t, cert, "Host certificate should not be nil")
	assert.NotEmpty(t, cert.Certificate, "Host certificate should not be empty")
	assert.NotEmpty(t, cert.PrivateKey, "Host private key should not be empty")
	assert.NotNil(t, cert.X509Cert, "Parsed X509 certificate should not be nil")
	assert.False(t, cert.X509Cert.IsCA, "Host certificate should not be marked as CA")
	assert.Contains(t, cert.X509Cert.DNSNames, hostname, "Certificate SAN should include hostname")
	assert.Equal(t, hostname, cert.X509Cert.Subject.CommonName, "Common name should match hostname")

	roots := x509.NewCertPool()
	roots.AddCert(ca.X509Cert)

	opts := x509.VerifyOptions{
		DNSName: hostname,
		Roots:   roots,
	}

	_, err = cert.X509Cert.Verify(opts)
	assert.NoError(t, err, "Certificate should be verified by CA")
}

func TestCertificateCaching(t *testing.T) {
	config := DefaultCertManagerConfig()
	ca, err := GenerateCA(config)
	assert.NoError(t, err, "Failed to generate CA")

	cm, err := NewCertificateManagerWithCA(ca, config)
	assert.NoError(t, err, "Failed to create certificate manager")

	hostname := "registry.npmjs.org"

	// First generation
	cert1, err := cm.GenerateCertForHost(hostname)
	assert.NoError(t, err, "Failed to generate first certificate")

	// Second generation should return cached certificate
	cert2, err := cm.GenerateCertForHost(hostname)
	assert.NoError(t, err, "Failed to generate second certificate")

	// Should be the same certificate (pointer equality)
	assert.Equal(t, cert1, cert2, "Second call should return cached certificate")
}

func TestGetTLSConfig(t *testing.T) {
	config := DefaultCertManagerConfig()
	ca, err := GenerateCA(config)
	assert.NoError(t, err, "Failed to generate CA")

	cm, err := NewCertificateManagerWithCA(ca, config)
	assert.NoError(t, err, "Failed to create certificate manager")

	hostname := "registry.npmjs.org"

	tlsConfig, err := cm.GetTLSConfig(hostname)
	assert.NoError(t, err, "Failed to get TLS config")

	assert.NotNil(t, tlsConfig, "TLS config should not be nil")

	assert.NotEmpty(t, tlsConfig.Certificates, "TLS config should have certificates")
	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion, "TLS min version should be TLS 1.2")
}

func TestCertificateExpiry(t *testing.T) {
	config := DefaultCertManagerConfig()
	config.HostCertValidityDays = 1

	ca, err := GenerateCA(config)
	assert.NoError(t, err, "Failed to generate CA")

	cm, err := NewCertificateManagerWithCA(ca, config)
	assert.NoError(t, err, "Failed to create certificate manager")

	cert, err := cm.GenerateCertForHost("example.com")
	assert.NoError(t, err, "Failed to generate certificate")

	// Certificate should not be expired with 1 hour threshold
	assert.False(t, cert.IsExpired(1*time.Hour), "Certificate should not be expired yet")

	// Certificate should be "expired" with threshold > validity period
	assert.True(t, cert.IsExpired(25*time.Hour), "Certificate should be considered expired with large threshold")
}

func TestCertManagerConfigValidation(t *testing.T) {
	config := CertManagerConfig{
		CAValidityDays:       0,
		HostCertValidityDays: 0,
		KeySize:              2048,
	}

	config.SetDefaults()
	err := config.Validate()
	assert.NoError(t, err, "Validate should not return error")

	assert.Equal(t, 365, config.CAValidityDays, "CAValidityDays should default to 365")
	assert.Equal(t, 1, config.HostCertValidityDays, "HostCertValidityDays should default to 1")
	assert.Equal(t, 2048, config.KeySize, "KeySize should default to 2048")

	config.KeySize = 1024
	err = config.Validate()
	assert.Error(t, err, "Validate should return error for key size less than 2048")
}

func TestNewCertificateManagerWithNilCA(t *testing.T) {
	config := DefaultCertManagerConfig()

	_, err := NewCertificateManagerWithCA(nil, config)
	if err == nil {
		t.Error("Expected error when creating manager with nil CA")
	}
}

func BenchmarkGenerateCA(b *testing.B) {
	config := DefaultCertManagerConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateCA(config)
		assert.NoError(b, err, "Failed to generate CA")
	}
}

func BenchmarkGenerateHostCert(b *testing.B) {
	config := DefaultCertManagerConfig()
	ca, err := GenerateCA(config)
	assert.NoError(b, err, "Failed to generate CA")

	cm, err := NewCertificateManagerWithCA(ca, config)
	assert.NoError(b, err, "Failed to create certificate manager")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cm.GenerateCertForHost("example.com")
		assert.NoError(b, err, "Failed to generate host certificate")
	}
}

func BenchmarkCacheOperations(b *testing.B) {
	cache := NewInMemoryCache()
	cert := &Certificate{
		Certificate: []byte("test cert"),
		PrivateKey:  []byte("test key"),
	}

	b.Run("Set", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cache.Set("example.com", cert)
		}
	})

	b.Run("Get", func(b *testing.B) {
		cache.Set("example.com", cert)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cache.Get("example.com")
		}
	})
}

func TestGenerateCA_WithoutMerge(t *testing.T) {
	config := DefaultCertManagerConfig()

	systemBundlePath := filepath.Join(t.TempDir(), "system.pem")
	assert.NoError(t, os.WriteFile(systemBundlePath, []byte("SYSTEM_CA_CERT\n"), 0600))

	original := os.Getenv("REQUESTS_CA_BUNDLE")
	assert.NoError(t, os.Setenv("REQUESTS_CA_BUNDLE", systemBundlePath))
	t.Cleanup(func() { _ = os.Setenv("REQUESTS_CA_BUNDLE", original) })

	ca, err := GenerateCA(config)
	assert.NoError(t, err, "Failed to generate CA")
	assert.False(t, strings.Contains(string(ca.Certificate), "SYSTEM_CA_CERT"), "CA should not include system bundle content when merge is disabled")
}

func TestGenerateCA_WithMergeConfig_DoesNotAlterCertificatePEM(t *testing.T) {
	config := DefaultCertManagerConfig()
	config.MergeWithSystemCABundle = true

	systemBundlePath := filepath.Join(t.TempDir(), "system.pem")
	assert.NoError(t, os.WriteFile(systemBundlePath, []byte("SYSTEM_CA_CERT\n"), 0600))

	original := os.Getenv("REQUESTS_CA_BUNDLE")
	assert.NoError(t, os.Setenv("REQUESTS_CA_BUNDLE", systemBundlePath))
	t.Cleanup(func() { _ = os.Setenv("REQUESTS_CA_BUNDLE", original) })

	ca, err := GenerateCA(config)
	assert.NoError(t, err, "Failed to generate CA")
	assert.False(t, strings.Contains(string(ca.Certificate), "SYSTEM_CA_CERT"), "GenerateCA should return only PMG CA certificate PEM")
}

func TestMergeWithSystemCABundle(t *testing.T) {
	systemBundlePath := filepath.Join(t.TempDir(), "system.pem")
	assert.NoError(t, os.WriteFile(systemBundlePath, []byte("SYSTEM_CA_CERT\n"), 0600))

	original := os.Getenv("REQUESTS_CA_BUNDLE")
	assert.NoError(t, os.Setenv("REQUESTS_CA_BUNDLE", systemBundlePath))
	t.Cleanup(func() { _ = os.Setenv("REQUESTS_CA_BUNDLE", original) })

	merged, err := MergeWithSystemCABundle([]byte("PMG_CA_CERT\n"))
	assert.NoError(t, err, "Failed to merge with system CA bundle")
	assert.True(t, strings.Contains(string(merged), "PMG_CA_CERT"), "Merged bundle should contain PMG CA content")
	assert.True(t, strings.Contains(string(merged), "SYSTEM_CA_CERT"), "Merged bundle should contain system CA content")
}

func TestSystemCABundleCandidatesForOS_WindowsIncludesCommonBundlePaths(t *testing.T) {
	env := map[string]string{
		"ProgramFiles":      `C:\Program Files`,
		"ProgramFiles(x86)": `C:\Program Files (x86)`,
		"SystemRoot":        `C:\Windows`,
	}

	candidates := systemCABundleCandidatesForOS("windows", func(k string) string { return env[k] })
	joined := strings.Join(candidates, "|")

	assert.Contains(t, joined, `Git/mingw64/ssl/certs/ca-bundle.crt`)
	assert.Contains(t, joined, `Git/usr/ssl/certs/ca-bundle.crt`)
	assert.Contains(t, joined, `Git/mingw32/ssl/certs/ca-bundle.crt`)
	assert.Contains(t, joined, `System32/curl-ca-bundle.crt`)
}

func TestSystemCABundleCandidatesForOS_DarwinIncludesKnownBundlePaths(t *testing.T) {
	candidates := systemCABundleCandidatesForOS("darwin", func(string) string { return "" })
	joined := strings.Join(candidates, "|")

	assert.Contains(t, joined, "/opt/homebrew/etc/openssl@3/cert.pem")
	assert.Contains(t, joined, "/usr/local/etc/openssl@3/cert.pem")
	assert.Contains(t, joined, "/etc/ssl/cert.pem")
}

func TestSystemCABundleCandidatesForOS_LinuxIncludesKnownBundlePaths(t *testing.T) {
	candidates := systemCABundleCandidatesForOS("linux", func(string) string { return "" })
	joined := strings.Join(candidates, "|")

	assert.Contains(t, joined, "/etc/ssl/certs/ca-certificates.crt")
	assert.Contains(t, joined, "/etc/pki/tls/certs/ca-bundle.crt")
	assert.Contains(t, joined, "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
	assert.Contains(t, joined, "/etc/ssl/ca-bundle.pem")
	assert.Contains(t, joined, "/etc/ssl/cert.pem")
}

func TestFirstReadablePath(t *testing.T) {
	tempDir := t.TempDir()

	readableFile1 := filepath.Join(tempDir, "ca1.pem")
	readableFile2 := filepath.Join(tempDir, "ca2.pem")
	dirPath := filepath.Join(tempDir, "certs")
	missingFile := filepath.Join(tempDir, "missing.pem")

	assert.NoError(t, os.MkdirAll(dirPath, 0o755))
	assert.NoError(t, os.WriteFile(readableFile1, []byte("CERT1"), 0o600))
	assert.NoError(t, os.WriteFile(readableFile2, []byte("CERT2"), 0o600))

	t.Run("returns first readable file and skips empty, directory, and missing", func(t *testing.T) {
		got := firstReadablePath("", dirPath, missingFile, readableFile1, readableFile2)
		assert.Equal(t, readableFile1, got)
	})

	t.Run("returns empty when no readable file exists", func(t *testing.T) {
		got := firstReadablePath("", dirPath, missingFile)
		assert.Equal(t, "", got)
	})
}
