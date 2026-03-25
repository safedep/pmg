//go:build linux
// +build linux

package platform

import (
	"os"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

// NewSandbox creates a platform-specific sandbox instance for Linux.
// Prefers Landlock (kernel 5.13+) with seccomp-notify for deny enforcement.
// Falls back to Bubblewrap if Landlock or seccomp-notify is unavailable.
// Set PMG_SANDBOX_DRIVER=bubblewrap to force Bubblewrap.
func NewSandbox() (sandbox.Sandbox, error) {
	if driver := os.Getenv("PMG_SANDBOX_DRIVER"); driver == "bubblewrap" {
		log.Debugf("PMG_SANDBOX_DRIVER=bubblewrap: forcing Bubblewrap sandbox")
		return newBubblewrapSandbox()
	}

	sb, err := newLandlockSandbox()
	if err == nil {
		log.Debugf("Using Landlock sandbox driver (ABI V%d)", sb.(*landlockSandbox).abi.Version)
		return sb, nil
	}

	log.Debugf("Landlock not available (%v), falling back to Bubblewrap", err)
	return newBubblewrapSandbox()
}
