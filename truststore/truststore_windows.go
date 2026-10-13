//go:build windows
// +build windows

package truststore

import (
	"crypto/x509"
	"fmt"
	"strings"
)

func userScopeSupportedPlatform() bool { return true }

func installPlatform(certPEM []byte, scope Scope) error {
	path, cleanup, err := writeTempCert(certPEM)
	if err != nil {
		return err
	}
	defer cleanup()

	args := []string{}
	if scope == ScopeUser {
		args = append(args, "-user")
	}
	args = append(args, "-addstore", "Root", path)

	if out, err := commandRunner("certutil", args...); err != nil {
		return fmt.Errorf("certutil -addstore failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func uninstallPlatform(commonName string, scope Scope) error {
	args := []string{}
	if scope == ScopeUser {
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

// statusPlatform reports which Root store holds this exact certificate.
func statusPlatform(cert *x509.Certificate) (bool, bool, error) {
	id := thumbprint(cert)
	return certInWindowsStore(id, true), certInWindowsStore(id, false), nil
}

// caTrustedPlatform looks the certificate up by its SHA-1 thumbprint in the user
// and the machine Root store. certutil identifies a certificate by this
// thumbprint, so a different certificate with the same name does not match.
func caTrustedPlatform(_ string, cert *x509.Certificate) error {
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
