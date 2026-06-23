package proxye2e

import (
	"testing"

	"github.com/safedep/pmg/config"
)

// TestCase is one end-to-end scenario. Config mutates the global PMG config for
// the case; Setup registers fixtures and verdicts; Exec drives traffic; Assert
// verifies the outcome.
type TestCase struct {
	Name           string
	PinnedVersions map[string]string
	Config         func(rc *config.RuntimeConfig)
	Setup          func(h *Harness)
	Exec           func(h *Harness) ExecResult
	Assert         func(t *testing.T, h *Harness, result ExecResult)
}

// RunCases runs each case serially. Serial execution is required because the
// interceptors read the global config singleton at request time, which the
// runner mutates per case.
func RunCases(t *testing.T, cases []TestCase) {
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			applyConfig(t, tc.Config)

			h := New(t, WithPinnedVersions(tc.PinnedVersions))
			defer h.Close()

			if tc.Setup != nil {
				tc.Setup(h)
			}

			var result ExecResult
			if tc.Exec != nil {
				result = tc.Exec(h)
			}

			if tc.Assert != nil {
				tc.Assert(t, h, result)
			}
		})
	}
}

// applyConfig resets the security-relevant config fields to a known hermetic
// baseline, applies the case override, then restores the original on cleanup so
// a developer's on-disk config never leaks into a case.
func applyConfig(t *testing.T, override func(rc *config.RuntimeConfig)) {
	t.Helper()

	rc := config.Get()
	saved := *rc
	t.Cleanup(func() { *rc = saved })

	rc.InsecureInstallation = false
	rc.Config.Paranoid = false
	rc.Config.TrustedPackages = nil
	rc.Config.DependencyCooldown = config.DependencyCooldownConfig{}

	if override != nil {
		override(rc)
	}

	if err := config.PreprocessTrustedPackages(&rc.Config); err != nil {
		t.Fatalf("failed to preprocess trusted packages: %v", err)
	}
}
