package cloudpolicy

import (
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	corev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/core/v1"
	recordv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/record/v1"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudpolicy/cloudpolicytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyDecisions(t *testing.T) {
	cfg := newTestConfig(t)
	soon := time.Now().Add(time.Hour)
	writeCache(t, cfg, cloudpolicytest.Policy(
		cloudpolicytest.Block("r_block", "pkg:npm/evil", "vers:npm/>=1.2.0|<2.0.0", "IR-2291"),
		cloudpolicytest.Trust("r_trust_evil", "pkg:npm/evil", "", soon,
			corev1.TrustScope_TRUST_SCOPE_MALWARE, corev1.TrustScope_TRUST_SCOPE_COOLDOWN),
		cloudpolicytest.Trust("r_malware", "pkg:npm/fp", "", soon, corev1.TrustScope_TRUST_SCOPE_MALWARE),
		cloudpolicytest.Trust("r_cooldown", "pkg:pypi/Fresh_Pkg", "", soon, corev1.TrustScope_TRUST_SCOPE_COOLDOWN),
		cloudpolicytest.Trust("r_vuln", "pkg:npm/vuln", "", soon, corev1.TrustScope_TRUST_SCOPE_VULNERABILITY),
		cloudpolicytest.Trust("r_expired", "pkg:npm/old", "", time.Now().Add(-time.Hour), corev1.TrustScope_TRUST_SCOPE_MALWARE),
	), 48)
	cfg.Config.BlockedPackages = []config.BlockedPackage{{Purl: "pkg:npm/@local/*", Reason: "local"}}
	p := newPolicy(Load(cfg, testTenant), cfg.Config.DependencyCooldown)

	pypi := packagev1.Ecosystem_ECOSYSTEM_PYPI
	tests := []struct {
		name        string
		ecosystem   packagev1.Ecosystem
		pkg         string
		version     string
		wantBlock   string
		wantMalware string
		wantCool    string
	}{
		{name: "a block entry wins over a trust entry", ecosystem: npm, pkg: "evil", version: "1.2.4", wantBlock: "r_block"},
		{name: "a version outside the block range", ecosystem: npm, pkg: "evil", version: "2.0.0",
			wantMalware: "r_trust_evil", wantCool: "r_trust_evil"},
		{name: "a local prefix block", ecosystem: npm, pkg: "@local/x", version: "1.0.0", wantBlock: "local:"},
		{name: "a malware trust entry", ecosystem: npm, pkg: "fp", version: "1.0.0", wantMalware: "r_malware"},
		{name: "a cooldown trust entry folds the name", ecosystem: pypi, pkg: "fresh-pkg", version: "1.0", wantCool: "r_cooldown"},
		{name: "a vulnerability trust entry changes no pmg decision", ecosystem: npm, pkg: "vuln", version: "1.0.0"},
		{name: "an expired trust entry does not apply", ecosystem: npm, pkg: "old", version: "1.0.0"},
		{name: "no rule", ecosystem: npm, pkg: "left-pad", version: "1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block, blocked := p.Block(tt.ecosystem, tt.pkg, tt.version)
			if tt.wantBlock == "" {
				assert.False(t, blocked)
			} else {
				require.True(t, blocked)
				assert.Contains(t, block.Rule.ID, tt.wantBlock)
			}

			malware, ok := p.TrustMalware(tt.ecosystem, tt.pkg, tt.version)
			assert.Equal(t, tt.wantMalware != "", ok)
			assert.Equal(t, tt.wantMalware, malware.Rule.ID)
			assert.Equal(t, tt.wantMalware, malware.Citation.GetRuleId())

			cooldown, ok := p.TrustCooldown(tt.ecosystem, tt.pkg, tt.version)
			assert.Equal(t, tt.wantCool != "", ok)
			assert.Equal(t, tt.wantCool, cooldown.Rule.ID)
		})
	}
}

func TestPolicyWithNoRules(t *testing.T) {
	var p *Policy
	_, ok := p.Block(npm, "evil", "1.0.0")
	assert.False(t, ok)
	assert.Nil(t, p.CooldownCitation())
	assert.Nil(t, p.Applied())

	p = FromConfig(&config.RuntimeConfig{})
	_, ok = p.Block(npm, "", "1.0.0")
	assert.False(t, ok)
}

func TestToolPolicyState(t *testing.T) {
	t.Run("cloud off sends no state", func(t *testing.T) {
		assert.Nil(t, ToolPolicyState(&Status{CloudOn: false}))
		assert.Nil(t, ToolPolicyState(nil))
	})

	t.Run("cloud.policy off reports disabled", func(t *testing.T) {
		cfg := newTestConfig(t)
		cfg.Config.Cloud.Policy = false

		state := ToolPolicyState(Load(cfg, testTenant))

		require.NotNil(t, state)
		assert.Equal(t, ToolName, state.GetToolName())
		assert.Equal(t, recordv1.ApplyState_APPLY_STATE_DISABLED, state.GetPolicy().GetState())
		assert.Zero(t, state.GetPolicy().GetRevision())
	})

	t.Run("an applied cache reports its revision", func(t *testing.T) {
		cfg := newTestConfig(t)
		writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 48)
		st := Load(cfg, testTenant)

		state := ToolPolicyState(st)

		report := state.GetPolicy()
		assert.Equal(t, recordv1.ApplyState_APPLY_STATE_APPLIED, report.GetState())
		assert.Equal(t, uint64(48), report.GetRevision())
		assert.Equal(t, uint64(12), report.GetDefaultPolicyRevision())
		assert.Equal(t, st.Applied.Digest, report.GetDigest())
		assert.Equal(t, st.CacheState.FetchedAt, report.GetFetchedAt().AsTime())
		assert.Equal(t, st.CacheState.StoredAt, report.GetAppliedAt().AsTime())
		assert.Empty(t, report.GetRejectedReason())
		assert.Empty(t, report.GetExceptions())
	})

	t.Run("a rejected cache reports the reason", func(t *testing.T) {
		cfg := newTestConfig(t)
		writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 48)
		require.NoError(t, cloudpolicytest.Write(cfg.CloudPolicyCacheDir(), cloudpolicytest.Policy(), cloudpolicytest.Header{
			Tenant: testTenant, MachineID: "another-machine", Revision: 49,
		}))

		report := ToolPolicyState(Load(cfg, testTenant)).GetPolicy()

		assert.Equal(t, recordv1.ApplyState_APPLY_STATE_REJECTED, report.GetState())
		assert.Equal(t, uint64(48), report.GetRevision())
		assert.NotEmpty(t, report.GetRejectedReason())
		assert.Nil(t, report.GetAppliedAt(), "pmg does not know when the previous file applied")
	})

	t.Run("no cache reports none", func(t *testing.T) {
		cfg := newTestConfig(t)

		report := ToolPolicyState(Load(cfg, testTenant)).GetPolicy()

		assert.Equal(t, recordv1.ApplyState_APPLY_STATE_NONE, report.GetState())
		assert.Nil(t, report.GetFetchedAt())
	})
}
