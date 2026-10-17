package platform

import (
	"context"
	"fmt"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

// execNetworkProbe reports how pmg sandbox exec applies a network policy on
// this host. The proxy by environment applies with every driver. Only some
// drivers confine every outbound connection to that proxy under
// network_via_proxy_only.
type execNetworkProbe struct {
	newSandbox func() (sandbox.Sandbox, error)
}

// NewExecNetworkProbe returns the probe for the driver NewSandbox picks.
func NewExecNetworkProbe() sandbox.Probe {
	return &execNetworkProbe{newSandbox: NewSandbox}
}

func (p *execNetworkProbe) Name() string { return sandbox.ProbeExecNetwork }

func (p *execNetworkProbe) Run(_ context.Context) sandbox.ProbeResult {
	sb, err := p.newSandbox()
	if err != nil {
		return sandbox.ProbeResult{
			Name:    sandbox.ProbeExecNetwork,
			Status:  sandbox.ProbeStatusFail,
			Summary: "no sandbox driver",
			Detail:  err.Error(),
			Fixes: []sandbox.ProbeFix{{
				Description: "pmg sandbox exec needs a sandbox driver. The driver probes above name what is missing.",
				Docs:        "https://github.com/safedep/pmg/blob/main/docs/sandbox-exec.md",
			}},
		}
	}
	defer func() {
		if err := sb.Close(); err != nil {
			log.Warnf("failed to close the %s sandbox after the probe: %v", sb.Name(), err)
		}
	}()

	if !driverConfinesOutbound(sb.Name()) {
		return sandbox.ProbeResult{
			Name:    sandbox.ProbeExecNetwork,
			Status:  sandbox.ProbeStatusWarn,
			Summary: fmt.Sprintf("proxy by environment only (%s)", sb.Name()),
			Detail:  "A program that ignores HTTP_PROXY and HTTPS_PROXY connects direct, and the network policy does not see it. This driver does not support network_via_proxy_only.",
			Fixes: []sandbox.ProbeFix{{
				Description: "Use the Landlock driver, which confines outbound connections to the proxy.",
				Command:     "PMG_SANDBOX_DRIVER=landlock pmg sandbox doctor",
				Docs:        "https://github.com/safedep/pmg/blob/main/docs/sandbox-exec.md",
			}, {
				Description: "Route every process through the enforcing daemon in the kernel.",
				Command:     "pmg proxy start --daemon --enforce",
				Docs:        "https://github.com/safedep/pmg/blob/main/docs/persistent-proxy.md",
			}},
		}
	}

	return sandbox.ProbeResult{
		Name:    sandbox.ProbeExecNetwork,
		Status:  sandbox.ProbeStatusOK,
		Summary: fmt.Sprintf("proxy by environment, confined with network_via_proxy_only (%s)", sb.Name()),
		Detail:  "The program gets the proxy through HTTP_PROXY and HTTPS_PROXY. A profile with network_via_proxy_only also refuses every outbound connection that does not go to the proxy.",
	}
}

// driverConfinesOutbound reports whether the driver applies
// network_via_proxy_only. Bubblewrap refuses the key.
func driverConfinesOutbound(driver sandbox.DriverName) bool {
	return driver == sandbox.DriverLandlock || driver == sandbox.DriverSeatbelt
}
