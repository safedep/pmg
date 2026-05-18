//go:build darwin
// +build darwin

package platform

import "github.com/safedep/pmg/sandbox"

// DefaultProbes returns the sandbox probes for the host platform (darwin).
func DefaultProbes() []sandbox.Probe {
	return []sandbox.Probe{
		NewSeatbeltProbe(),
		NewSeatbeltCanaryProbe(),
	}
}
