//go:build windows

package platform

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func caUserScopeSupported() bool { return true }

func installCA(cert *x509.Certificate, scope TrustScope) error {
	path, cleanup, err := writeTempCert(cert)
	if err != nil {
		return err
	}
	defer cleanup()

	args := []string{}
	if scope == TrustScopeUser {
		args = append(args, "-user")
	}
	args = append(args, "-addstore", "Root", path)

	if out, err := commandRunner("certutil", args...); err != nil {
		return fmt.Errorf("certutil -addstore failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func uninstallCA(commonName string, scope TrustScope) error {
	args := []string{}
	if scope == TrustScopeUser {
		args = append(args, "-user")
	}
	args = append(args, "-delstore", "Root", commonName)

	if out, err := commandRunner("certutil", args...); err != nil {
		msg := strings.TrimSpace(string(out))
		lower := strings.ToLower(msg)
		if strings.Contains(lower, "cannot find") || strings.Contains(msg, "0x80092004") {
			return nil
		}
		return fmt.Errorf("certutil -delstore failed: %w: %s", err, msg)
	}
	return nil
}

// caStores reports which Root store holds this exact certificate.
func caStores(cert *x509.Certificate) (bool, bool, error) {
	id := thumbprint(cert)
	return certInWindowsStore(id, true), certInWindowsStore(id, false), nil
}

// verifyCATrusted looks the certificate up by its SHA-1 thumbprint in the user
// and the machine Root store. certutil identifies a certificate by this
// thumbprint, so a different certificate with the same name does not match.
func verifyCATrusted(_ string, cert *x509.Certificate) error {
	id := thumbprint(cert)
	if certInWindowsStore(id, true) || certInWindowsStore(id, false) {
		return nil
	}
	return fmt.Errorf("%w: no Root store holds the certificate with thumbprint %s", ErrCANotTrusted, id)
}

// certInWindowsStore reports whether certID, a common name or a thumbprint,
// matches a certificate in the Root store.
func certInWindowsStore(certID string, userScope bool) bool {
	args := []string{}
	if userScope {
		args = append(args, "-user")
	}
	args = append(args, "-store", "Root", certID)

	_, err := commandRunner("certutil", args...)
	return err == nil
}

// caBundleCandidates lists the bundles that Git for Windows and curl ship.
// Windows itself keeps no bundle file.
func caBundleCandidates() []string {
	var candidates []string
	if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
		candidates = append(candidates,
			filepath.Join(programFiles, "Git", "mingw64", "ssl", "certs", "ca-bundle.crt"),
			filepath.Join(programFiles, "Git", "usr", "ssl", "certs", "ca-bundle.crt"),
		)
	}
	if programFilesX86 := os.Getenv("ProgramFiles(x86)"); programFilesX86 != "" {
		candidates = append(candidates,
			filepath.Join(programFilesX86, "Git", "mingw32", "ssl", "certs", "ca-bundle.crt"),
		)
	}
	if systemRoot := os.Getenv("SystemRoot"); systemRoot != "" {
		candidates = append(candidates, filepath.Join(systemRoot, "System32", "curl-ca-bundle.crt"))
	}
	return candidates
}
