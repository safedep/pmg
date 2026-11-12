package proxye2e

import (
	"path/filepath"
	"testing"

	specv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/spec/v1"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudpolicy"
	"github.com/safedep/pmg/internal/cloudpolicy/cloudpolicytest"
	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/internal/platform/platformtest"
	"github.com/stretchr/testify/require"
)

// policyEndpointID is the endpoint id of a case with a cloud policy. The
// cache header names the machine id that pmg derives from it.
const policyEndpointID = "proxye2e-endpoint"

// TestCase is one end-to-end scenario. Config mutates the global PMG config for
// the case; Setup registers fixtures and verdicts; Exec drives traffic; Assert
// verifies the outcome.
type TestCase struct {
	Name           string
	PinnedVersions map[string]string
	// Options configure the harness beyond the pinned versions, for example
	// the transparent listener a redirected client needs.
	Options []Option
	Config  func(rc *config.RuntimeConfig)

	// Policy is the resolved policy of the tenant, with no header. The runner
	// writes it as the policy cache and loads it through the real loader of
	// cloudpolicy, with cloud.enabled and cloud.policy on. Config runs after,
	// so a case can turn cloud.policy off again.
	Policy *specv1.ResolvedPolicy

	// StateDir sets PMG_STATE_DIR to a folder of the case, so the runner
	// writes Policy into the state directory cache.
	StateDir bool

	// SudoPolicy runs the case as root that a user reached through sudo. The
	// runner writes it as the policy cache of that user, which a sudo run also
	// reads.
	SudoPolicy *specv1.ResolvedPolicy

	Setup  func(h *Harness)
	Exec   func(h *Harness) ExecResult
	Assert func(t *testing.T, h *Harness, result ExecResult)
}

// RunCases runs each case serially. Serial execution is required because the
// interceptors read the global config singleton at request time, which the
// runner mutates per case.
func RunCases(t *testing.T, cases []TestCase) {
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			opts := []Option{WithPinnedVersions(tc.PinnedVersions)}
			if tc.Policy != nil || tc.SudoPolicy != nil {
				opts = append(opts, WithPolicy(loadPolicy(t, tc)))
			} else {
				applyConfig(t, tc.Config)
			}

			h := New(t, append(opts, tc.Options...)...)
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

// loadPolicy gives the case a config folder of its own, writes the policies of
// the case as policy caches, and loads them as the root command of pmg does.
func loadPolicy(t *testing.T, tc TestCase) cloudpolicy.Source {
	t.Helper()

	// Cleanups run last in first out: the config reloads after the
	// environment is back.
	t.Cleanup(config.Reload)
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	if tc.StateDir {
		t.Setenv("PMG_STATE_DIR", t.TempDir())
	}
	var sudoCache string
	if tc.SudoPolicy != nil {
		// Under sudo, the cache directory resolves to the home of root.
		t.Setenv("PMG_CACHE_DIR", t.TempDir())
		home := t.TempDir()
		platformtest.StubSudo(t, home)
		sudoCache = filepath.Join(platform.HomeDirs(home).Config, "safedep", "pmg", "cloud-policy")
	}
	config.Reload()

	applyConfig(t, func(rc *config.RuntimeConfig) {
		rc.Config.Cloud.Enabled = true
		rc.Config.Cloud.Policy = true
		rc.Config.Cloud.EndpointID = policyEndpointID
		if tc.Config != nil {
			tc.Config(rc)
		}
	})

	cfg := config.Get()
	if tc.Policy != nil {
		writePolicy(t, cfg.CloudPolicyCacheDir(), tc.Policy)
	}
	if tc.SudoPolicy != nil {
		writePolicy(t, sudoCache, tc.SudoPolicy)
	}

	rt := &cloudpolicy.Runtime{}
	rt.LoadAtStartForTenant(cfg, "")
	rt.Publish(cfg)
	return rt
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
	rc.Config.AdvisoryMessage = ""
	rc.Config.Proxy.Registries = nil
	rc.Config.BlockedPackages = nil
	rc.Config.Cloud.Enabled = false
	rc.Config.Cloud.Policy = false

	if override != nil {
		override(rc)
	}

	if err := config.PreprocessPackageRefs(&rc.Config); err != nil {
		t.Fatalf("failed to preprocess trusted packages: %v", err)
	}
}

func writePolicy(t *testing.T, dir string, policy *specv1.ResolvedPolicy) {
	t.Helper()
	machineID, err := cloudpolicytest.MachineID(policyEndpointID)
	require.NoError(t, err)
	require.NoError(t, cloudpolicytest.Write(dir, policy, cloudpolicytest.Header{
		Tenant:                "proxye2e.acme.safedep.io",
		MachineID:             machineID,
		Revision:              48,
		DefaultPolicyRevision: 12,
	}))
}
