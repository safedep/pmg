package platform

import (
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

// ActiveDriver returns the driver that NewSandbox selects on this host. ok is
// false when no driver is available.
func ActiveDriver() (driver sandbox.DriverName, ok bool) {
	sb, err := NewSandbox()
	if err != nil {
		return "", false
	}
	defer func() {
		if err := sb.Close(); err != nil {
			log.Debugf("failed to close the %s sandbox after the driver check: %v", sb.Name(), err)
		}
	}()

	if !sb.IsAvailable() {
		return "", false
	}

	return sb.Name(), true
}
