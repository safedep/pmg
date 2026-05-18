//go:build linux
// +build linux

package platform

import (
	"context"
	"strings"

	"github.com/safedep/pmg/sandbox"
)

type bwrapProbe struct {
	env probeEnv
}

// NewBwrapProbe returns a probe that verifies `bwrap --version` runs.
func NewBwrapProbe() sandbox.Probe {
	return &bwrapProbe{env: defaultProbeEnv{}}
}

func (p *bwrapProbe) Name() string { return sandbox.ProbeBwrapDriver }

func (p *bwrapProbe) Run(ctx context.Context) sandbox.ProbeResult {
	path, err := p.env.lookPath("bwrap")
	if err != nil {
		return sandbox.ProbeResult{
			Name:    sandbox.ProbeBwrapDriver,
			Status:  sandbox.ProbeStatusFail,
			Summary: "bwrap not found in PATH",
			Detail:  err.Error(),
			Fixes:   []sandbox.ProbeFix{bubblewrapInstallFix()},
		}
	}

	out, err := p.env.runCommand(ctx, path, "--version")
	if err != nil {
		return sandbox.ProbeResult{
			Name:    sandbox.ProbeBwrapDriver,
			Status:  sandbox.ProbeStatusFail,
			Summary: "bwrap --version failed",
			Detail:  strings.TrimSpace(string(out)) + ": " + err.Error(),
			Fixes: []sandbox.ProbeFix{{
				Description: "Reinstall bubblewrap and confirm unprivileged user namespaces are enabled.",
				Command:     "bwrap --version",
			}},
		}
	}

	return sandbox.ProbeResult{
		Name:    sandbox.ProbeBwrapDriver,
		Status:  sandbox.ProbeStatusOK,
		Summary: strings.TrimSpace(string(out)),
	}
}
