//go:build linux
// +build linux

package platform

import (
	"context"
	"strings"

	"github.com/safedep/pmg/sandbox"
)

const apparmorUsernsSysctlPath = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"

type apparmorProbe struct {
	env  probeEnv
	path string
}

// NewAppArmorUsernsProbe returns a probe that warns when AppArmor restricts
// unprivileged user namespaces (which breaks bwrap-based sandboxing).
func NewAppArmorUsernsProbe() sandbox.Probe {
	return &apparmorProbe{env: defaultProbeEnv{}, path: apparmorUsernsSysctlPath}
}

func (p *apparmorProbe) Name() string { return sandbox.ProbeAppArmorUserns }

func (p *apparmorProbe) Run(_ context.Context) sandbox.ProbeResult {
	data, err := p.env.readFile(p.path)
	if err != nil {
		return sandbox.ProbeResult{
			Name:    sandbox.ProbeAppArmorUserns,
			Status:  sandbox.ProbeStatusSkipped,
			Summary: "AppArmor userns sysctl not present",
			Detail:  err.Error(),
		}
	}

	value := strings.TrimSpace(string(data))
	if value == "0" {
		return sandbox.ProbeResult{
			Name:    sandbox.ProbeAppArmorUserns,
			Status:  sandbox.ProbeStatusOK,
			Summary: "Unprivileged user namespaces are not restricted by AppArmor",
		}
	}

	return sandbox.ProbeResult{
		Name:    sandbox.ProbeAppArmorUserns,
		Status:  sandbox.ProbeStatusWarn,
		Summary: "AppArmor restricts unprivileged user namespaces (value=" + value + ")",
		Detail: "landlock fails with `shim: install seccomp: ... permission denied` and bwrap with " +
			"`setting up uid map: Permission denied` until an AppArmor profile permits pmg or the sysctl is relaxed.",
		Fixes: []sandbox.ProbeFix{
			{
				Description: "Create an AppArmor profile granting pmg the userns permission (recommended), then reload it.",
				Command:     "sudo apparmor_parser -r /etc/apparmor.d/pmg",
				Docs:        "https://github.com/safedep/pmg/blob/main/docs/sandbox.md#apparmor-blocks-the-landlock-driver-ubuntu-2310",
			},
			{
				Description: "Temporarily relax the restriction system-wide (until next reboot).",
				Command:     "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0",
				Docs:        "https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces",
			},
		},
	}
}
