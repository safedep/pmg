package certmanager

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	caCertFileName = "ca-cert.pem"
	caKeyFileName  = "ca-key.pem"

	// proxyCABundleFileName is the merged CA bundle (PMG CA + system roots) that
	// proxy clients trust via SSL_CERT_FILE/NODE_EXTRA_CA_CERTS. It is distinct
	// from caCertFileName, which is just the PMG CA. Owned here so callers don't
	// invent their own names.
	proxyCABundleFileName = "proxy-ca.pem"
)

func CACertPath(dir string) string { return filepath.Join(dir, caCertFileName) }
func CAKeyPath(dir string) string  { return filepath.Join(dir, caKeyFileName) }

// ProxyCABundlePath returns the stable, machine-local path of the merged CA
// bundle. Used by the persistent proxy, whose daemon/env/stop processes all
// reference the same file for the proxy's lifetime.
func ProxyCABundlePath(dir string) string { return filepath.Join(dir, proxyCABundleFileName) }

// EphemeralProxyCABundlePath returns a per-process temp path for the merged CA
// bundle. Used by the per-command flow, which writes a throwaway bundle and
// removes it on exit; the pid keeps concurrent runs from colliding.
func EphemeralProxyCABundlePath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("pmg-%d-%s", os.Getpid(), proxyCABundleFileName))
}

// PersistentCACertManagerConfig returns the config for the on-disk,
// system-trusted CA. The root is long-lived (10 years) because rotating an
// installed, trusted root is expensive; leaf certs remain short (1 day).
func PersistentCACertManagerConfig() CertManagerConfig {
	c := DefaultCertManagerConfig()
	c.CAValidityDays = 3650
	return c
}

// SaveCA writes the CA certificate (0644) and private key (0600) to dir.
// Only the pure PMG CA is persisted — not the system-bundle-merged PEM.
func SaveCA(dir string, ca *Certificate) error {
	if ca == nil {
		return fmt.Errorf("ca certificate is nil")
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create config dir %s: %w", dir, err)
	}

	if err := os.WriteFile(CACertPath(dir), ca.Certificate, 0o644); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Remove any pre-existing key first so the new file is created fresh with
	// 0600. os.WriteFile preserves an existing file's mode, which could otherwise
	// leave a group/world-readable private key behind on a --force re-install.
	if err := os.Remove(CAKeyPath(dir)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to reset CA private key file: %w", err)
	}
	if err := os.WriteFile(CAKeyPath(dir), ca.PrivateKey, 0o600); err != nil {
		return fmt.Errorf("failed to write CA private key: %w", err)
	}

	return nil
}

// LoadCA reads and parses the persisted CA from dir. When a file is missing
// the returned error wraps os.ErrNotExist so callers can use errors.Is.
func LoadCA(dir string) (*Certificate, error) {
	certPEM, err := os.ReadFile(CACertPath(dir))
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(CAKeyPath(dir))
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key: %w", err)
	}

	parsed, err := parseCertificate(&Certificate{Certificate: certPEM, PrivateKey: keyPEM})
	if err != nil {
		return nil, fmt.Errorf("failed to parse persisted CA: %w", err)
	}

	return parsed, nil
}
