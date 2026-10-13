// Package truststore installs and removes PMG's MITM CA certificate in the
// operating-system trust store. Per-OS behavior lives in build-tagged files
// (truststore_darwin.go, truststore_linux.go, truststore_windows.go) mirroring
// the sandbox/platform package; this file holds the OS-agnostic surface.
package truststore

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/proxy/certmanager"
)

// Scope selects which trust store to operate on.
type Scope int

const (
	// ScopeUser is the per-user trust store (no elevation). Unsupported on Linux.
	ScopeUser Scope = iota
	// ScopeSystem is the machine-wide trust store (PMG elevates the write).
	ScopeSystem
)

func (s Scope) String() string {
	if s == ScopeSystem {
		return "system"
	}
	return "user"
}

// ErrUserScopeUnsupported is returned by Install/Uninstall when per-user trust
// is not a platform concept (Linux). Callers treat it as informational.
var ErrUserScopeUnsupported = errors.New("user-scope trust store is not supported on this platform")

// commandRunner runs an external trust-store tool. Overridable in tests.
var commandRunner = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// runElevated prefixes sudo on Unix (unless already root) so only the privileged
// system-store write is elevated. Windows has no sudo and relies on an elevated
// prompt, so the command runs as-is.
func runElevated(name string, args ...string) ([]byte, error) {
	if runtime.GOOS != "windows" && !platform.IsPrivileged() {
		log.Infof("Elevating via sudo to modify the system trust store")
		return commandRunner("sudo", append([]string{name}, args...)...)
	}
	return commandRunner(name, args...)
}

// Install adds certPEM (a PEM-encoded CA certificate) to the OS trust store.
func Install(certPEM []byte, scope Scope) error { return installPlatform(certPEM, scope) }

// Uninstall removes the certificate matched by commonName from the OS trust store.
func Uninstall(commonName string, scope Scope) error { return uninstallPlatform(commonName, scope) }

// Status reports which stores trust the CA persisted in configDir. A store
// counts only when the OS trusts that exact certificate. A different
// certificate with the same name does not count, because a TLS client rejects
// what the CA signs. With no CA on disk, no store trusts it.
func Status(configDir string) (user bool, system bool, err error) {
	certPath := certmanager.CACertPath(configDir)
	cert, err := readCert(certPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	user, system, err = statusPlatform(cert)
	if err != nil || (!user && !system) {
		return false, false, err
	}
	if err := caTrustedPlatform(certPath, cert); err != nil {
		if errors.Is(err, ErrCANotTrusted) {
			return false, false, nil
		}
		return false, false, err
	}
	return user, system, nil
}

// UserScopeSupported reports whether the platform has a per-user trust store
// (false on Linux). Consumers use it to interpret "not trusted" correctly.
func UserScopeSupported() bool { return userScopeSupportedPlatform() }

// ErrCANotTrusted is returned when the OS trust store does not trust the
// persisted PMG CA.
var ErrCANotTrusted = errors.New("the OS trust store does not trust the PMG CA")

// GoTrustsCA returns nil when Go can verify TLS from a PMG proxy that signs
// with the CA persisted in configDir. On macOS and Windows, PMG makes go read
// only the OS trust store (see packagemanager.EnvVarForProxy), so the OS store
// must trust this exact CA. On Linux go reads SSL_CERT_FILE, so any CA works.
func GoTrustsCA(configDir string) error {
	if !UserScopeSupported() {
		return nil
	}
	ca, err := certmanager.LoadUsableCA(configDir)
	if err != nil {
		return err
	}
	return caTrustedPlatform(certmanager.CACertPath(configDir), ca.X509Cert)
}

func readCert(path string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCert(certPEM)
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM certificate found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return cert, nil
}
