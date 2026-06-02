// Package truststore installs and removes PMG's MITM CA certificate in the
// operating-system trust store. Per-OS behavior lives in build-tagged files
// (truststore_darwin.go, truststore_linux.go, truststore_windows.go) mirroring
// the sandbox/platform package; this file holds the OS-agnostic surface.
package truststore

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
)

// Scope selects which trust store to operate on.
type Scope int

const (
	// ScopeUser is the per-user trust store (no elevation). Unsupported on Linux.
	ScopeUser Scope = iota
	// ScopeSystem is the machine-wide trust store (requires sudo/admin).
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

// Install adds certPEM (a PEM-encoded CA certificate) to the OS trust store.
func Install(certPEM []byte, scope Scope) error { return installPlatform(certPEM, scope) }

// Uninstall removes the certificate matched by commonName from the OS trust store.
func Uninstall(commonName string, scope Scope) error { return uninstallPlatform(commonName, scope) }

// Status reports whether the certificate matched by commonName is trusted in the
// user and/or system store. It is best-effort; callers may treat errors as not trusted.
func Status(commonName string) (user bool, system bool, err error) {
	return statusPlatform(commonName)
}

// UserScopeSupported reports whether the platform has a per-user trust store
// (false on Linux). Consumers use it to interpret "not trusted" correctly.
func UserScopeSupported() bool { return userScopeSupportedPlatform() }

func unsupportedPlatformError() error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.UnsupportedPlatform).
		WithHumanError("trust store operations are not supported on this platform").
		WithHelp("Use PMG's default env-var trust injection, or install the CA manually").
		Wrap(errors.New("unsupported platform"))
}

// writeTempCert writes certPEM to a temp file and returns its path and a cleanup
// func. OS trust tools (security, certutil) require a file path argument.
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
