// Package platform exposes Render for translating a SandboxPolicy into a
// driver-specific representation. Each driver's renderer is OS-gated (it
// imports OS-specific syscalls), so Render returns an error on a non-native
// host rather than silently producing an inaccurate result.
package platform

import (
	"fmt"
	"runtime"

	"github.com/safedep/pmg/sandbox"
)

// Render dispatches to the OS-native renderer for driver. On a non-native
// host it returns a descriptive error so callers (e.g. `profile show
// --driver=...`) can surface it cleanly.
func Render(driver sandbox.DriverName, policy *sandbox.SandboxPolicy) ([]byte, error) {
	switch driver {
	case sandbox.DriverSeatbelt:
		return renderSeatbelt(policy)
	case sandbox.DriverBubblewrap:
		return renderBubblewrap(policy)
	case sandbox.DriverLandlock:
		return renderLandlock(policy)
	default:
		return nil, fmt.Errorf("unknown sandbox driver: %s", driver)
	}
}

func driverUnavailable(driver sandbox.DriverName) error {
	return fmt.Errorf("driver %s is not available on %s/%s", driver, runtime.GOOS, runtime.GOARCH)
}
