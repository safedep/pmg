//go:build darwin || linux || windows
// +build darwin linux windows

package truststore

import (
	"fmt"
	"os"
)

// writeTempCert writes certPEM to a temp file and returns its path and a cleanup
// func. The OS trust tools (macOS security, Windows certutil, Linux install)
// take a file path argument, so the cert is staged in a user-owned temp file
// before the elevated store write.
func writeTempCert(certPEM []byte) (string, func(), error) {
	noop := func() {}

	f, err := os.CreateTemp("", "pmg-ca-*.pem")
	if err != nil {
		return "", noop, fmt.Errorf("failed to create temp cert file: %w", err)
	}

	if _, err := f.Write(certPEM); err != nil {
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
