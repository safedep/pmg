package platform

import (
	"crypto/x509"
	"errors"
	"os"
)

// CAScope selects the OS trust store that holds the PMG CA.
type CAScope int

const (
	// CAScopeUser is the per-user trust store. It needs no elevation.
	// Linux has none.
	CAScopeUser CAScope = iota
	// CAScopeSystem is the machine-wide trust store. PMG elevates the write.
	CAScopeSystem
)

func (s CAScope) String() string {
	if s == CAScopeSystem {
		return "system"
	}
	return "user"
}

// ErrCAUserScopeUnsupported is returned when the platform has no per-user
// trust store (Linux). Callers treat it as information.
var ErrCAUserScopeUnsupported = errors.New("user-scope trust store is not supported on this platform")

// ErrCANotTrusted is returned when the OS trust store does not trust the CA.
var ErrCANotTrusted = errors.New("the OS trust store does not trust the PMG CA")

// InstallCA adds the CA certificate to the trust store of scope.
func InstallCA(cert *x509.Certificate, scope CAScope) error { return installCA(cert, scope) }

// UninstallCA removes every certificate named commonName from the trust store
// of scope. A store that holds none is not an error.
func UninstallCA(commonName string, scope CAScope) error { return uninstallCA(commonName, scope) }

// CAStores reports which trust store holds this exact certificate. A
// different certificate with the same name does not count.
func CAStores(cert *x509.Certificate) (user, system bool, err error) { return caStores(cert) }

// VerifyCATrusted returns nil when the OS trusts this exact certificate, the
// one stored at certPath. It wraps ErrCANotTrusted with the cause otherwise.
func VerifyCATrusted(certPath string, cert *x509.Certificate) error {
	return verifyCATrusted(certPath, cert)
}

// CAUserScopeSupported reports whether the platform has a per-user trust
// store. Linux has none.
func CAUserScopeSupported() bool { return caUserScopeSupported() }

// SystemCABundlePath returns the first readable CA bundle of the OS, or ""
// when the host has none. An inherited SSL_CERT_FILE or CURL_CA_BUNDLE does
// not count, because it can name a bundle without the PMG CA.
func SystemCABundlePath() string { return firstReadableFile(caBundleCandidates()...) }

// CABundlePath returns the CA bundle that the user's tools read: the one in
// SSL_CERT_FILE or CURL_CA_BUNDLE, else the bundle of the OS. It returns ""
// when none is readable.
func CABundlePath() string {
	return firstReadableFile(append([]string{os.Getenv("SSL_CERT_FILE"), os.Getenv("CURL_CA_BUNDLE")}, caBundleCandidates()...)...)
}

// firstReadableFile returns the first of paths that is a regular file the
// process can open, or "".
func firstReadableFile(paths ...string) string {
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		_ = f.Close()
		return path
	}
	return ""
}
