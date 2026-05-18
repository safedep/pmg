//go:build darwin
// +build darwin

package platform

import (
	"context"

	"github.com/safedep/pmg/sandbox"
)

type seatbeltCanaryProbe struct {
	factory    canarySandboxFactory
	cmdFactory canaryCommandFactory
}

// NewSeatbeltCanaryProbe runs the per-driver Seatbelt smoke test.
func NewSeatbeltCanaryProbe() sandbox.Probe {
	return &seatbeltCanaryProbe{
		factory:    func() (sandbox.Sandbox, error) { return NewSeatbeltSandbox() },
		cmdFactory: defaultCanaryCommand,
	}
}

func (p *seatbeltCanaryProbe) Name() string { return sandbox.ProbeSeatbeltCanary }

func (p *seatbeltCanaryProbe) Run(ctx context.Context) sandbox.ProbeResult {
	return runCanary(ctx, sandbox.ProbeSeatbeltCanary, sandbox.DriverSeatbelt, p.factory, p.cmdFactory)
}
