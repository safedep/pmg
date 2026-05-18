//go:build linux
// +build linux

package platform

import "github.com/safedep/pmg/sandbox"

// DefaultProbes returns the sandbox probes for the host platform (linux).
func DefaultProbes() []sandbox.Probe {
	return []sandbox.Probe{
		NewBwrapProbe(),
		NewLandlockProbe(),
		NewAppArmorUsernsProbe(),
		NewBwrapCanaryProbe(),
		NewLandlockCanaryProbe(),
	}
}
