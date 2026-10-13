//go:build darwin || linux || windows

package platform

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
)

// commandRunner runs an external trust store tool. Tests replace it.
var commandRunner = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// writeTempCert writes the certificate as PEM to a temp file and returns its
// path and a cleanup func. The OS trust tools (macOS security, Windows
// certutil, Linux install) take a file path, so the certificate is staged in a
// user-owned temp file before the elevated store write.
func writeTempCert(cert *x509.Certificate) (string, func(), error) {
	noop := func() {}

	f, err := os.CreateTemp("", "pmg-ca-*.pem")
	if err != nil {
		return "", noop, fmt.Errorf("failed to create temp cert file: %w", err)
	}

	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", noop, fmt.Errorf("failed to write temp cert file: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", noop, fmt.Errorf("failed to close temp cert file: %w", err)
	}

	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}
