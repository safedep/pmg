//go:build darwin
// +build darwin

package platform

import "github.com/safedep/pmg/sandbox"

func renderSeatbelt(p *sandbox.SandboxPolicy) ([]byte, error) {
	return RenderSeatbelt(p)
}

func renderBubblewrap(p *sandbox.SandboxPolicy) ([]byte, error) {
	return nil, driverUnavailable(sandbox.DriverBubblewrap)
}

func renderLandlock(p *sandbox.SandboxPolicy) ([]byte, error) {
	return nil, driverUnavailable(sandbox.DriverLandlock)
}
