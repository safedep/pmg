//go:build darwin || windows

package platform

import (
	"crypto/sha1"
	"crypto/x509"
	"fmt"
)

// thumbprint is the uppercase SHA-1 hex digest of the certificate. macOS and
// Windows identify a certificate in a store by this value.
func thumbprint(cert *x509.Certificate) string {
	return fmt.Sprintf("%X", sha1.Sum(cert.Raw))
}
