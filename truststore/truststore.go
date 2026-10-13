// Package truststore installs PMG's MITM CA in the OS trust store and checks
// that the OS trusts the CA that PMG persisted. The per-OS work lives in
// internal/platform. This package ties it to the persisted keypair.
package truststore

import (
	"errors"
	"os"

	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/proxy/certmanager"
)

// Scope selects the OS trust store. It aliases the platform type, so callers
// outside this module can name it. internal/platform is closed to them.
type Scope = platform.CAScope

const (
	ScopeUser   = platform.CAScopeUser
	ScopeSystem = platform.CAScopeSystem
)

// ErrUserScopeUnsupported is returned by Install and Uninstall when the
// platform has no per-user trust store (Linux).
var ErrUserScopeUnsupported = platform.ErrCAUserScopeUnsupported

// ErrCANotTrusted is returned when the OS trust store does not trust the
// persisted PMG CA.
var ErrCANotTrusted = platform.ErrCANotTrusted

// Tests replace these to drive Status and GoTrustsCA on any OS.
var (
	caStores        = platform.CAStores
	verifyCATrusted = platform.VerifyCATrusted
)

// Install adds certPEM (a PEM-encoded CA certificate) to the OS trust store.
func Install(certPEM []byte, scope Scope) error {
	cert, err := certmanager.ParseCertPEM(certPEM)
	if err != nil {
		return err
	}
	return platform.InstallCA(cert, scope)
}

// Uninstall removes every certificate named commonName from the OS trust store.
func Uninstall(commonName string, scope Scope) error {
	return platform.UninstallCA(commonName, scope)
}

// Status reports which stores trust the CA persisted in configDir. A store
// counts only when the OS trusts that exact certificate. A different
// certificate with the same name does not count, because a TLS client rejects
// what the CA signs. With no CA on disk, no store trusts it.
func Status(configDir string) (user bool, system bool, err error) {
	cert, err := certmanager.LoadCACert(configDir)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	user, system, err = caStores(cert)
	if err != nil || (!user && !system) {
		return false, false, err
	}
	if err := verifyCATrusted(certmanager.CACertPath(configDir), cert); err != nil {
		if errors.Is(err, ErrCANotTrusted) {
			return false, false, nil
		}
		return false, false, err
	}
	return user, system, nil
}

// UserScopeSupported reports whether the platform has a per-user trust store
// (false on Linux). Consumers use it to interpret "not trusted" correctly.
func UserScopeSupported() bool { return platform.CAUserScopeSupported() }

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
	return verifyCATrusted(certmanager.CACertPath(configDir), ca.X509Cert)
}
