//go:build linux
// +build linux

package platform

import (
	"fmt"
	"os"
	"runtime"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

// NewSandbox creates a platform-specific sandbox instance for Linux.
// Prefers Landlock (kernel 5.13+) with seccomp-notify for deny enforcement.
// Falls back to Bubblewrap if Landlock or seccomp-notify is unavailable.
// Set PMG_SANDBOX_DRIVER=bubblewrap to force Bubblewrap, or
// PMG_SANDBOX_DRIVER=landlock to force Landlock (no fallback — fails if
// Landlock is unavailable).
func NewSandbox() (sandbox.Sandbox, error) {
	if err := requireSupportedArch(); err != nil {
		return nil, err
	}

	switch sandbox.DriverName(os.Getenv("PMG_SANDBOX_DRIVER")) {
	case sandbox.DriverBubblewrap:
		log.Debugf("PMG_SANDBOX_DRIVER=bubblewrap: forcing Bubblewrap sandbox")
		return newBubblewrapSandbox()
	case sandbox.DriverLandlock:
		log.Debugf("PMG_SANDBOX_DRIVER=landlock: forcing Landlock sandbox")
		return newLandlockSandbox()
	}

	sb, err := newLandlockSandbox()
	if err == nil {
		log.Debugf("Using Landlock sandbox driver (ABI V%d)", sb.(*landlockSandbox).abi.Version)
		return sb, nil
	}

	log.Debugf("Landlock not available (%v), falling back to Bubblewrap", err)
	return newBubblewrapSandbox()
}

// NewBubblewrapSandbox returns a Bubblewrap-backed sandbox instance regardless
// of platform driver selection. Useful for per-driver diagnostics.
func NewBubblewrapSandbox() (sandbox.Sandbox, error) {
	if err := requireSupportedArch(); err != nil {
		return nil, err
	}
	return newBubblewrapSandbox()
}

// NewLandlockSandbox returns a Landlock-backed sandbox instance regardless of
// platform driver selection. Useful for per-driver diagnostics.
func NewLandlockSandbox() (sandbox.Sandbox, error) {
	if err := requireSupportedArch(); err != nil {
		return nil, err
	}
	return newLandlockSandbox()
}

// Supported reports whether PMG has a sandbox for this OS and architecture.
func Supported() bool { return requireSupportedArch() == nil }

// requireSupportedArch fails closed where the seccomp filter cannot read
// syscall arguments. There it cannot block unix sockets or namespaces.
func requireSupportedArch() error {
	if !seccompArgFiltering {
		return fmt.Errorf("sandbox not supported on linux/%s", runtime.GOARCH)
	}
	return nil
}
