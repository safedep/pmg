package platform

import (
	"context"
	"fmt"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/sandbox"
)

// execNetworkProbe reports whether pmg sandbox exec runs on this host. The
// exec profile confines every outbound connection to the proxy with
// network_via_proxy_only, and only some drivers support it.
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
			Summary: fmt.Sprintf("%s cannot confine outbound to the proxy", sb.Name()),
			Detail:  "The exec profile sets network_via_proxy_only, and this driver does not support it, so pmg sandbox exec refuses to run.",
			Fixes: []sandbox.ProbeFix{{
				Description: "Use the Landlock driver, which confines outbound connections to the proxy.",
				Command:     "PMG_SANDBOX_DRIVER=landlock pmg sandbox doctor",
				Docs:        "https://github.com/safedep/pmg/blob/main/docs/sandbox-exec.md",
			}},
		}
	}

	return sandbox.ProbeResult{
		Name:    sandbox.ProbeExecNetwork,
		Status:  sandbox.ProbeStatusOK,
		Summary: fmt.Sprintf("confined to the proxy (%s)", sb.Name()),
		Detail:  "The program gets the proxy through HTTP_PROXY and HTTPS_PROXY. The driver refuses every outbound connection that does not go to the proxy, except loopback.",
	}
}

// driverConfinesOutbound reports whether the driver applies
// network_via_proxy_only. Bubblewrap refuses the key.
func driverConfinesOutbound(driver sandbox.DriverName) bool {
	return driver == sandbox.DriverLandlock || driver == sandbox.DriverSeatbelt
}
