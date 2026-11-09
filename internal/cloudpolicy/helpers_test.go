package cloudpolicy

import (
	"testing"

	specv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/spec/v1"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudpolicy/cloudpolicytest"
	"github.com/stretchr/testify/require"
)

const (
	testTenant     = "platform-eng.acme.safedep.io"
	testEndpointID = "cloudpolicy-test"
)

// newTestConfig returns the global config with a config folder of its own,
// cloud.enabled and cloud.policy on, and a fixed endpoint id.
func newTestConfig(t *testing.T) *config.RuntimeConfig {
	t.Helper()

	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	config.Reload()
	t.Cleanup(config.Reload)

	cfg := config.Get()
	cfg.Config.Cloud.Enabled = true
	cfg.Config.Cloud.Policy = true
	cfg.Config.Cloud.EndpointID = testEndpointID
	cfg.Config.DependencyCooldown = config.DependencyCooldownConfig{Enabled: true, Days: 2}
	return cfg
}

func testMachineID(t *testing.T) string {
	t.Helper()
	id, err := cloudpolicytest.MachineID(testEndpointID)
	require.NoError(t, err)
	return id
}

// writeCache commits policy as the cache of cfg, for the test tenant and
// this machine, at revision.
func writeCache(t *testing.T, cfg *config.RuntimeConfig, policy *specv1.ResolvedPolicy, revision uint64) {
	t.Helper()
	require.NoError(t, cloudpolicytest.Write(cfg.CloudPolicyCacheDir(), policy, cloudpolicytest.Header{
		Tenant:                testTenant,
		MachineID:             testMachineID(t),
		Revision:              revision,
		DefaultPolicyRevision: 12,
	}))
}

// noLogin stands for a machine with no cloud login, as on CI.
func noLogin() string { return "" }
