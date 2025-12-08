package certmanager

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// Certificate represents a TLS certificate with its private key
// Both certificate and private key are stored in PEM-encoded format
type Certificate struct {
	// PEM encoded certificate
	Certificate []byte

	// PEM encoded private key
	PrivateKey []byte

	// Parsed X.509 certificate
	X509Cert *x509.Certificate

	// Parsed private key
	PrivKey crypto.PrivateKey
}

// CertificateCache defines the interface for certificate caching
type CertificateCache interface {
	// Get retrieves a cached certificate for the given hostname
	Get(hostname string) (*Certificate, bool)

	// Set stores a certificate for the given hostname
	Set(hostname string, cert *Certificate)

	// Clear removes all cached certificates
	Clear()

	// Size returns the number of cached certificates
	Size() int
}

// CertificateManager handles TLS certificate lifecycle management
type CertificateManager interface {
	// GetCA returns the Certificate Authority certificate and key
	GetCA() (*Certificate, error)

	// GenerateCertForHost creates a certificate for the given hostname
	// Uses caching to avoid regeneration of certificates
	// The certificate is signed by the CA and includes the hostname in the SAN
	GenerateCertForHost(hostname string) (*Certificate, error)

	// GetTLSConfig returns a tls.Config for the given hostname
	// This is a convenience method that generates/retrieves the certificate
	// and creates a tls.Config
	GetTLSConfig(hostname string) (*tls.Config, error)
}

// CertManagerConfig holds configuration for certificate generation
type CertManagerConfig struct {
	// CAValidityDays specifies how many days the CA certificate is valid
	CAValidityDays int

	// HostCertValidityDays specifies how many days host certificates are valid
	HostCertValidityDays int

	// KeySize specifies the RSA key size in bits
	KeySize int
}

// DefaultCertManagerConfig returns a configuration with reasonable defaults
func DefaultCertManagerConfig() CertManagerConfig {
	return CertManagerConfig{
		CAValidityDays:       365,
		HostCertValidityDays: 1,
		KeySize:              2048,
	}
}

// SetDefaults sets reasonable defaults for zero values in the configuration
func (c *CertManagerConfig) SetDefaults() {
	if c.CAValidityDays <= 0 {
		c.CAValidityDays = 365
	}

	if c.HostCertValidityDays <= 0 {
		c.HostCertValidityDays = 1
	}

	// Default to 2048 bits if key size is not set
	if c.KeySize == 0 {
		c.KeySize = 2048
	}
}

// Validate checks if the configuration is valid after defaults have been set
func (c *CertManagerConfig) Validate() error {
	if c.CAValidityDays <= 0 {
		return fmt.Errorf("CA validity days must be greater than 0: %d", c.CAValidityDays)
	}

	if c.HostCertValidityDays <= 0 {
		return fmt.Errorf("host certificate validity days must be greater than 0: %d", c.HostCertValidityDays)
	}

	if c.KeySize < 2048 {
		return fmt.Errorf("key size must be at least 2048 bits: %d", c.KeySize)
	}

	return nil
}

// IsExpired checks if a certificate is expired or will expire within the given threshold
func (c *Certificate) IsExpired(threshold time.Duration) bool {
	if c.X509Cert == nil {
		return true
	}
	expiryTime := c.X509Cert.NotAfter
	return time.Until(expiryTime) < threshold
}
