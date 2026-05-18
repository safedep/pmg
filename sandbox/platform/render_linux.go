//go:build linux
// +build linux

package platform

import "github.com/safedep/pmg/sandbox"

func renderSeatbelt(p *sandbox.SandboxPolicy) ([]byte, error) {
	return nil, driverUnavailable(sandbox.DriverSeatbelt)
}

func renderBubblewrap(p *sandbox.SandboxPolicy) ([]byte, error) {
	return RenderBubblewrap(p)
}

func renderLandlock(p *sandbox.SandboxPolicy) ([]byte, error) {
	return RenderLandlock(p)
}
