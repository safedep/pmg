package certmanager

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/dry/log"
)

const (
	// ProxyCACommonName is the X.509 subject common name for the PMG proxy root CA.
	ProxyCACommonName = "PMG Proxy CA"

	proxyCACertFilename   = "proxy-ca.pem"
	proxyCAKeyFilename    = "proxy-ca-key.pem"
	proxyCABundleFilename = "proxy-ca-bundle.pem"
)

// ProxyCAPaths returns filesystem paths for the persisted proxy CA material.
func ProxyCAPaths(configDir string) (certPath, keyPath, bundlePath string) {
	return filepath.Join(configDir, proxyCACertFilename),
		filepath.Join(configDir, proxyCAKeyFilename),
		filepath.Join(configDir, proxyCABundleFilename)
}

// LoadOrCreatePersistedCA loads the PMG proxy root CA from configDir or creates it.
func LoadOrCreatePersistedCA(configDir string) (*Certificate, error) {
	if configDir == "" {
		return nil, fmt.Errorf("config directory cannot be empty")
	}

	certPath, keyPath, _ := ProxyCAPaths(configDir)

	if fileExists(certPath) && fileExists(keyPath) {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("read proxy CA certificate %s: %w", certPath, err)
		}

		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read proxy CA private key %s: %w", keyPath, err)
		}

		caCert, err := parseCertificate(&Certificate{
			Certificate: certPEM,
			PrivateKey:  keyPEM,
		})
		if err != nil {
			return nil, err
		}

		if !caCert.IsExpired(certExpiryThreshold) {
			return caCert, nil
		}

		log.Warnf(
			"Persisted proxy CA expired and was regenerated; trust the new CA with: pmg setup install --proxy-ca",
		)
	}

	return generateAndWritePersistedCA(configDir, certPath, keyPath)
}

func generateAndWritePersistedCA(configDir, certPath, keyPath string) (*Certificate, error) {
	caCert, err := GenerateCA(DefaultCertManagerConfig())
	if err != nil {
		return nil, fmt.Errorf("generate proxy CA: %w", err)
	}

	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("create config directory %s: %w", configDir, err)
	}

	if err := os.WriteFile(certPath, caCert.Certificate, 0o600); err != nil {
		return nil, fmt.Errorf("write proxy CA certificate %s: %w", certPath, err)
	}

	if err := os.WriteFile(keyPath, caCert.PrivateKey, 0o600); err != nil {
		return nil, fmt.Errorf("write proxy CA private key %s: %w", keyPath, err)
	}

	return caCert, nil
}

// WriteProxyCABundle writes the merged PMG+system CA bundle used by child tools.
func WriteProxyCABundle(configDir string, rootCA *Certificate) (string, error) {
	if rootCA == nil {
		return "", fmt.Errorf("root CA cannot be nil")
	}

	certPath, _, bundlePath := ProxyCAPaths(configDir)
	if proxyCABundleFresh(bundlePath, certPath) {
		return bundlePath, nil
	}

	bundle, err := mergeSystemCABundle(rootCA)
	if err != nil {
		return "", fmt.Errorf("merge proxy CA bundle: %w", err)
	}

	if err := os.WriteFile(bundlePath, bundle.Certificate, 0o600); err != nil {
		return "", fmt.Errorf("write proxy CA bundle %s: %w", bundlePath, err)
	}

	return bundlePath, nil
}

func proxyCABundleFresh(bundlePath, certPath string) bool {
	bundleInfo, err := os.Stat(bundlePath)
	if err != nil || bundleInfo.IsDir() {
		return false
	}

	certInfo, err := os.Stat(certPath)
	if err != nil || certInfo.IsDir() {
		return false
	}

	return bundleInfo.ModTime().After(certInfo.ModTime())
}

// RemovePersistedCA deletes persisted proxy CA files from configDir.
func RemovePersistedCA(configDir string) error {
	certPath, keyPath, bundlePath := ProxyCAPaths(configDir)

	var firstErr error
	for _, path := range []string{certPath, keyPath, bundlePath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			if firstErr == nil {
				firstErr = fmt.Errorf("remove %s: %w", path, err)
			}
		}
	}

	return firstErr
}

// ProxyCARootCertPath returns the path to the persisted root CA certificate PEM.
func ProxyCARootCertPath(configDir string) string {
	certPath, _, _ := ProxyCAPaths(configDir)
	return certPath
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
