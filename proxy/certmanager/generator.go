package certmanager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// certManager implements the CertificateManager interface
type certManager struct {
	ca     *Certificate
	cache  CertificateCache
	config CertManagerConfig
}

// NewCertificateManagerWithCA creates a new certificate manager with an existing CA certificate
func NewCertificateManagerWithCA(ca *Certificate, config CertManagerConfig) (CertificateManager, error) {
	if ca == nil {
		return nil, fmt.Errorf("CA certificate cannot be nil")
	}

	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if ca.X509Cert == nil || ca.PrivKey == nil {
		parsedCA, err := parseCertificate(ca)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}

		ca = parsedCA
	}

	return &certManager{
		ca:     ca,
		cache:  NewInMemoryCache(),
		config: config,
	}, nil
}

// GetCA returns the Certificate Authority certificate
func (cm *certManager) GetCA() (*Certificate, error) {
	return cm.ca, nil
}

// GenerateCertForHost creates a certificate for the given hostname
// Uses caching to avoid regeneration
func (cm *certManager) GenerateCertForHost(hostname string) (*Certificate, error) {
	if cached, found := cm.cache.Get(hostname); found {
		if !cached.IsExpired(1 * time.Hour) {
			return cached, nil
		}
	}

	cert, err := cm.generateHostCert(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate for %s: %w", hostname, err)
	}

	cm.cache.Set(hostname, cert)

	return cert, nil
}

// GetTLSConfig returns a tls.Config for the given hostname
func (cm *certManager) GetTLSConfig(hostname string) (*tls.Config, error) {
	cert, err := cm.GenerateCertForHost(hostname)
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create tls.Certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func (cm *certManager) generateHostCert(hostname string) (*Certificate, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, cm.config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(cm.config.HostCertValidityDays) * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	caPrivKey, ok := cm.ca.PrivKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA private key is not RSA")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, cm.ca.X509Cert, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	return &Certificate{
		Certificate: certPEM,
		PrivateKey:  privKeyPEM,
		X509Cert:    x509Cert,
		PrivKey:     privKey,
	}, nil
}

// GenerateCA generates a new self-signed CA certificate using the given configuration
func GenerateCA(config CertManagerConfig) (*Certificate, error) {
	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	privKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(config.CAValidityDays) * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "PMG Proxy CA",
			Organization: []string{"SafeDep PMG"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	return &Certificate{
		Certificate: certPEM,
		PrivateKey:  privKeyPEM,
		X509Cert:    x509Cert,
		PrivKey:     privKey,
	}, nil
}

func parseCertificate(cert *Certificate) (*Certificate, error) {
	certBlock, _ := pem.Decode(cert.Certificate)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X509 certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(cert.PrivateKey)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM private key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return &Certificate{
		Certificate: cert.Certificate,
		PrivateKey:  cert.PrivateKey,
		X509Cert:    x509Cert,
		PrivKey:     privKey,
	}, nil
}

// ParseTLSCertificate converts a Certificate to a tls.Certificate
// This is useful for integrating with libraries that expect tls.Certificate
func ParseTLSCertificate(cert *Certificate) (tls.Certificate, error) {
	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create X509 key pair: %w", err)
	}

	// Populate Leaf field if we have the parsed X.509 certificate
	// This is important for libraries (like goproxy) that need to inspect the certificate
	if cert.X509Cert != nil {
		tlsCert.Leaf = cert.X509Cert
	}

	return tlsCert, nil
}
