//go:build !darwin && !linux
// +build !darwin,!linux

package platform

import "github.com/safedep/pmg/sandbox"

func renderSeatbelt(p *sandbox.SandboxPolicy) ([]byte, error) {
	return nil, driverUnavailable(sandbox.DriverSeatbelt)
}

func renderBubblewrap(p *sandbox.SandboxPolicy) ([]byte, error) {
	return nil, driverUnavailable(sandbox.DriverBubblewrap)
}

func renderLandlock(p *sandbox.SandboxPolicy) ([]byte, error) {
	return nil, driverUnavailable(sandbox.DriverLandlock)
}
