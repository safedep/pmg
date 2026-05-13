//go:build linux
// +build linux

package platform

import (
	"os"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

var (
	landlockSandboxFactory   = newLandlockSandbox
	bubblewrapSandboxFactory = func() (sandbox.Sandbox, error) {
		return newBubblewrapSandbox()
	}
)

// NewSandbox creates a platform-specific sandbox instance for Linux.
// Prefers Landlock (kernel 5.13+) with seccomp-notify for deny enforcement.
// Falls back to Bubblewrap if Landlock or seccomp-notify is unavailable.
// Set PMG_SANDBOX_DRIVER=bubblewrap to force Bubblewrap, or
// PMG_SANDBOX_DRIVER=landlock to force Landlock (no fallback — fails if
// Landlock is unavailable).
func NewSandbox() (sandbox.Sandbox, error) {
	switch os.Getenv("PMG_SANDBOX_DRIVER") {
	case "bubblewrap":
		log.Debugf("PMG_SANDBOX_DRIVER=bubblewrap: forcing Bubblewrap sandbox")
		return bubblewrapSandboxFactory()
	case "landlock":
		log.Debugf("PMG_SANDBOX_DRIVER=landlock: forcing Landlock sandbox")
		return landlockSandboxFactory()
	}

	sb, err := landlockSandboxFactory()
	if err == nil {
		if ll, ok := sb.(*landlockSandbox); ok {
			log.Debugf("Using Landlock sandbox driver (ABI V%d)", ll.abi.Version)
		} else {
			log.Debugf("Using Landlock sandbox driver")
		}
		return sb, nil
	}

	log.Debugf("Landlock not available (%v), falling back to Bubblewrap", err)
	return bubblewrapSandboxFactory()
}
