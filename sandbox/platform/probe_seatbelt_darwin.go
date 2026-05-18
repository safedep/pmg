//go:build darwin
// +build darwin

package platform

import (
	"context"

	"github.com/safedep/pmg/sandbox"
)

type seatbeltProbe struct {
	env probeEnv
}

// NewSeatbeltProbe returns a probe that verifies sandbox-exec is present and
// executable on this host.
func NewSeatbeltProbe() sandbox.Probe {
	return &seatbeltProbe{env: defaultProbeEnv{}}
}

func (p *seatbeltProbe) Name() string { return sandbox.ProbeSeatbeltDriver }

func (p *seatbeltProbe) Run(_ context.Context) sandbox.ProbeResult {
	path, err := p.env.lookPath("sandbox-exec")
	if err != nil {
		return sandbox.ProbeResult{
			Name:    sandbox.ProbeSeatbeltDriver,
			Status:  sandbox.ProbeStatusFail,
			Summary: "sandbox-exec not found in PATH",
			Detail:  err.Error(),
			Fixes: []sandbox.ProbeFix{{
				Description: "sandbox-exec ships with macOS. Verify your PATH includes /usr/bin.",
				Command:     "ls -l /usr/bin/sandbox-exec",
			}},
		}
	}

	info, err := p.env.statExecutable(path)
	if err != nil {
		return sandbox.ProbeResult{
			Name:    sandbox.ProbeSeatbeltDriver,
			Status:  sandbox.ProbeStatusFail,
			Summary: "sandbox-exec is not accessible",
			Detail:  err.Error(),
			Fixes: []sandbox.ProbeFix{{
				Description: "Inspect the binary permissions and SIP state.",
				Command:     "ls -l " + path,
			}},
		}
	}

	if info.Mode()&0o111 == 0 {
		return sandbox.ProbeResult{
			Name:    sandbox.ProbeSeatbeltDriver,
			Status:  sandbox.ProbeStatusFail,
			Summary: "sandbox-exec is not executable",
			Detail:  "found at " + path,
			Fixes: []sandbox.ProbeFix{{
				Description: "Restore execute bit on sandbox-exec or reinstall the OS toolchain.",
				Command:     "chmod +x " + path,
			}},
		}
	}

	return sandbox.ProbeResult{
		Name:    sandbox.ProbeSeatbeltDriver,
		Status:  sandbox.ProbeStatusOK,
		Summary: "sandbox-exec available at " + path,
	}
}
