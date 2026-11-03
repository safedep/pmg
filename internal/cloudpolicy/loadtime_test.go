package cloudpolicy

import (
	"fmt"
	"testing"
	"time"

	corev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/core/v1"
	recordv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/record/v1"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudpolicy/cloudpolicytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	loadTimeRules = 10_000

	// loadTimeLimit catches a large regression, not a small one, so that a
	// slow CI runner does not fail the test.
	loadTimeLimit = 2 * time.Second
)

// largePolicyCache writes a cache with 10,000 package rules, the limit of a
// resolved policy: blocks, prefix blocks, and trust entries with a range or
// a version.
func largePolicyCache(tb testing.TB, cfg *config.RuntimeConfig, machineID string) {
	tb.Helper()

	expires := time.Now().Add(30 * 24 * time.Hour)
	rules := make([]*corev1.PackageRule, 0, loadTimeRules)
	for i := range loadTimeRules {
		id := fmt.Sprintf("r_%08d", i)
		switch i % 4 {
		case 0:
			rules = append(rules, cloudpolicytest.Block(id, fmt.Sprintf("pkg:npm/evil-%d", i), "", "incident"))
		case 1:
			rules = append(rules, cloudpolicytest.Block(id, fmt.Sprintf("pkg:npm/@scope%d/*", i), "", "incident"))
		case 2:
			rules = append(rules, cloudpolicytest.Trust(id, fmt.Sprintf("pkg:pypi/fp-%d", i), "vers:pypi/>=1.0|<2.0",
				expires, corev1.TrustScope_TRUST_SCOPE_MALWARE))
		default:
			rules = append(rules, cloudpolicytest.Trust(id, fmt.Sprintf("pkg:npm/fp-%d@1.0.0", i), "",
				expires, corev1.TrustScope_TRUST_SCOPE_COOLDOWN))
		}
	}

	require.NoError(tb, cloudpolicytest.Write(cfg.CloudPolicyCacheDir(), cloudpolicytest.Policy(rules...), cloudpolicytest.Header{
		Tenant:    testTenant,
		MachineID: machineID,
		Revision:  48,
	}))
}

func TestLoadTimeOfTenThousandRules(t *testing.T) {
	cfg := newTestConfig(t)
	largePolicyCache(t, cfg, testMachineID(t))

	start := time.Now()
	st := Load(cfg, testTenant)
	elapsed := time.Since(start)

	require.Equal(t, recordv1.ApplyState_APPLY_STATE_APPLIED, st.State)
	assert.Equal(t, loadTimeRules, st.BlockEntries+st.TrustEntries)
	t.Logf("the load of %d package rules took %s", loadTimeRules, elapsed)
	if raceEnabled {
		t.Skip("the race detector makes the load many times slower, so the limit does not apply")
	}
	assert.Lessf(t, elapsed, loadTimeLimit, "the load of %d package rules took %s", loadTimeRules, elapsed)
}

// BenchmarkLoad measures the load of a cache with 10,000 package rules
// through the real loader: the read of the cache, project.Decode and
// match.NewIndex. pmg pays it once for each proxied command.
func BenchmarkLoad(b *testing.B) {
	b.Setenv("PMG_CONFIG_DIR", b.TempDir())
	config.Reload()
	b.Cleanup(config.Reload)

	cfg := config.Get()
	cfg.Config.Cloud.Enabled = true
	cfg.Config.Cloud.Policy = true
	cfg.Config.Cloud.EndpointID = testEndpointID
	machineID, err := cloudpolicytest.MachineID(testEndpointID)
	require.NoError(b, err)
	largePolicyCache(b, cfg, machineID)

	b.ReportAllocs()
	for b.Loop() {
		st := Load(cfg, testTenant)
		require.Equal(b, loadTimeRules, st.BlockEntries+st.TrustEntries)
	}
}
