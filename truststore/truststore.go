// Package truststore installs and removes PMG's MITM CA certificate in the
// operating-system trust store. Per-OS behavior lives in build-tagged files
// (truststore_darwin.go, truststore_linux.go, truststore_windows.go) mirroring
// the sandbox/platform package; this file holds the OS-agnostic surface.
package truststore

import (
	"errors"
	"os"
	"os/exec"
	"runtime"

	"github.com/safedep/dry/log"
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

var euid = os.Geteuid

// runElevated prefixes sudo on Unix (unless already root) so only the privileged
// system-store write is elevated. Windows has no sudo and relies on an elevated
// prompt, so the command runs as-is.
func runElevated(name string, args ...string) ([]byte, error) {
	if runtime.GOOS != "windows" && euid() != 0 {
		log.Infof("Elevating via sudo to modify the system trust store")
		return commandRunner("sudo", append([]string{name}, args...)...)
	}
	return commandRunner(name, args...)
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
