//go:build linux
// +build linux

package platform

import (
	"context"

	"github.com/safedep/pmg/sandbox"
)

type linuxCanaryProbe struct {
	name       string
	driver     sandbox.DriverName
	factory    canarySandboxFactory
	cmdFactory canaryCommandFactory
}

// NewBwrapCanaryProbe runs the per-driver Bubblewrap smoke test.
func NewBwrapCanaryProbe() sandbox.Probe {
	return &linuxCanaryProbe{
		name:       sandbox.ProbeBwrapCanary,
		driver:     sandbox.DriverBubblewrap,
		factory:    func() (sandbox.Sandbox, error) { return NewBubblewrapSandbox() },
		cmdFactory: defaultCanaryCommand,
	}
}

// NewLandlockCanaryProbe runs the per-driver Landlock smoke test.
func NewLandlockCanaryProbe() sandbox.Probe {
	return &linuxCanaryProbe{
		name:       sandbox.ProbeLandlockCanary,
		driver:     sandbox.DriverLandlock,
		factory:    func() (sandbox.Sandbox, error) { return NewLandlockSandbox() },
		cmdFactory: defaultCanaryCommand,
	}
}

func (p *linuxCanaryProbe) Name() string { return p.name }

func (p *linuxCanaryProbe) Run(ctx context.Context) sandbox.ProbeResult {
	return runCanary(ctx, p.name, p.driver, p.factory, p.cmdFactory)
}
