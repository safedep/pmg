//go:build linux
// +build linux

package platform

import (
	"context"
	"fmt"

	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"

	"github.com/safedep/pmg/sandbox"
)

// landlockABIDetector decouples ABI lookup from the syscall for tests.
type landlockABIDetector func() (int, error)

func defaultLandlockABIDetector() (int, error) {
	v, err := llsyscall.LandlockGetABIVersion()
	if err != nil {
		return 0, err
	}
	return v, nil
}

type landlockProbe struct {
	detect landlockABIDetector
}

// NewLandlockProbe returns a probe that reports the Landlock ABI level.
func NewLandlockProbe() sandbox.Probe {
	return &landlockProbe{detect: defaultLandlockABIDetector}
}

func (p *landlockProbe) Name() string { return sandbox.ProbeLandlockDriver }

func (p *landlockProbe) Run(_ context.Context) sandbox.ProbeResult {
	version, err := p.detect()
	if err != nil {
		return sandbox.ProbeResult{
			Name:    sandbox.ProbeLandlockDriver,
			Status:  sandbox.ProbeStatusFail,
			Summary: "Landlock not supported by kernel",
			Detail:  err.Error(),
			Fixes: []sandbox.ProbeFix{{
				Description: "Landlock requires Linux 5.13+. Upgrade your kernel or use bwrap.",
				Docs:        "https://docs.kernel.org/userspace-api/landlock.html",
			}},
		}
	}

	if version <= 0 {
		return sandbox.ProbeResult{
			Name:    sandbox.ProbeLandlockDriver,
			Status:  sandbox.ProbeStatusFail,
			Summary: fmt.Sprintf("Landlock ABI %d (unsupported)", version),
			Fixes: []sandbox.ProbeFix{{
				Description: "Upgrade your kernel to 5.13 or newer.",
				Docs:        "https://docs.kernel.org/userspace-api/landlock.html",
			}},
		}
	}

	if version < 3 {
		return sandbox.ProbeResult{
			Name:    sandbox.ProbeLandlockDriver,
			Status:  sandbox.ProbeStatusWarn,
			Summary: fmt.Sprintf("Landlock ABI V%d (limited features)", version),
			Detail:  "ABI < 3 lacks truncate and refer support; some policies may not enforce as expected.",
			Fixes: []sandbox.ProbeFix{{
				Description: "Upgrade to Linux 5.19+ (ABI 3) or 6.2+ (ABI 4) for full coverage.",
				Docs:        "https://docs.kernel.org/userspace-api/landlock.html",
			}},
		}
	}

	return sandbox.ProbeResult{
		Name:    sandbox.ProbeLandlockDriver,
		Status:  sandbox.ProbeStatusOK,
		Summary: fmt.Sprintf("Landlock ABI V%d", version),
	}
}
