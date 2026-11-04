package cloudpolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	corev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/core/v1"
	recordv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/record/v1"
	"github.com/safedep/dry/cloud/configsync"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudpolicy/cloudpolicytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var npm = packagev1.Ecosystem_ECOSYSTEM_NPM

func blockEvil() *corev1.PackageRule {
	return cloudpolicytest.Block("r_9c1", "pkg:npm/evil", "", "IR-2291 credential stealer")
}

func TestLoadDisabled(t *testing.T) {
	tests := []struct {
		name     string
		cloudOn  bool
		policyOn bool
	}{
		{name: "cloud.policy off", cloudOn: true, policyOn: false},
		{name: "cloud.enabled off", cloudOn: false, policyOn: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestConfig(t)
			writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 48)
			cfg.Config.Cloud.Enabled = tt.cloudOn
			cfg.Config.Cloud.Policy = tt.policyOn
			cfg.Config.BlockedPackages = []config.BlockedPackage{{Purl: "pkg:npm/local-evil"}}
			require.NoError(t, config.PreprocessPackageRefs(&cfg.Config))

			st := Load(cfg, testTenant)

			assert.Equal(t, recordv1.ApplyState_APPLY_STATE_DISABLED, st.State)
			assert.Nil(t, st.Applied)
			assert.Nil(t, st.Projection)

			p := newPolicy(st, cfg.Config.DependencyCooldown)
			_, blocked := p.Block(npm, "evil", "1.0.0")
			assert.False(t, blocked, "pmg ignores the cache")
			local, blocked := p.Block(npm, "local-evil", "1.0.0")
			assert.True(t, blocked, "the local block list applies")
			assert.False(t, local.Cloud())
			assert.Nil(t, local.Citation)
		})
	}
}

func TestLoadNoCache(t *testing.T) {
	cfg := newTestConfig(t)

	st := Load(cfg, testTenant)

	assert.Equal(t, recordv1.ApplyState_APPLY_STATE_NONE, st.State)
	assert.ErrorIs(t, st.LoadErr, configsync.ErrNoCache)
	assert.Nil(t, st.Applied)
}

func TestLoadApplied(t *testing.T) {
	cfg := newTestConfig(t)
	writeCache(t, cfg, cloudpolicytest.Policy(
		blockEvil(),
		cloudpolicytest.Trust("r_t1", "pkg:npm/good", "", time.Now().Add(time.Hour), corev1.TrustScope_TRUST_SCOPE_MALWARE),
	), 48)

	st := Load(cfg, testTenant)

	require.Equal(t, recordv1.ApplyState_APPLY_STATE_APPLIED, st.State)
	require.NotNil(t, st.Applied)
	assert.Equal(t, testTenant, st.Applied.Tenant)
	assert.Equal(t, uint64(48), st.Applied.Revision)
	assert.Equal(t, uint64(12), st.Applied.DefaultPolicyRevision)
	assert.Equal(t, st.CacheState.Digest, st.Applied.Digest)
	assert.Equal(t, 1, st.BlockEntries)
	assert.Equal(t, 1, st.TrustEntries)
	assert.Equal(t, cfg.CloudPolicyCacheDir(), st.CacheDir)

	m, blocked := newPolicy(st, cfg.Config.DependencyCooldown).Block(npm, "evil", "1.2.4")
	require.True(t, blocked)
	assert.True(t, m.Cloud())
	assert.Equal(t, "r_9c1", m.Rule.ID)
	assert.Equal(t, "IR-2291 credential stealer", m.Rule.Reason)
	assert.Equal(t, uint64(48), m.Citation.GetRevision())
	assert.Equal(t, uint64(12), m.Citation.GetDefaultPolicyRevision())
	assert.Equal(t, st.Applied.Digest, m.Citation.GetDigest())
	assert.Equal(t, "r_9c1", m.Citation.GetRuleId())
	assert.Empty(t, m.Citation.GetPath())
	assert.Equal(t, recordv1.Layer_LAYER_UNSPECIFIED, m.Citation.GetLayer())
}

func TestLoadWithNoLoginSkipsOnlyTheTenantCheck(t *testing.T) {
	cfg := newTestConfig(t)
	writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 48)

	st := Load(cfg, "")

	assert.Equal(t, recordv1.ApplyState_APPLY_STATE_APPLIED, st.State)
	assert.Equal(t, 1, st.BlockEntries)
}

func TestLoadRefusesTheCacheOfAnotherTenant(t *testing.T) {
	cfg := newTestConfig(t)
	writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 48)

	st := Load(cfg, "other.acme.safedep.io")

	assert.Equal(t, recordv1.ApplyState_APPLY_STATE_NONE, st.State)
	assert.ErrorIs(t, st.LoadErr, configsync.ErrTenantMismatch)
	assert.Nil(t, st.Applied)
	assert.Zero(t, st.BlockEntries)
}

func TestLoadRejectsAPolicyOfAnotherMachine(t *testing.T) {
	cfg := newTestConfig(t)
	require.NoError(t, cloudpolicytest.Write(cfg.CloudPolicyCacheDir(), cloudpolicytest.Policy(blockEvil()), cloudpolicytest.Header{
		Tenant:    testTenant,
		MachineID: "another-machine",
		Revision:  48,
	}))

	st := Load(cfg, testTenant)

	assert.Equal(t, recordv1.ApplyState_APPLY_STATE_REJECTED, st.State)
	assert.Nil(t, st.Applied, "no previous file, so the tool baseline applies")
	assert.Zero(t, st.BlockEntries)
	assert.NotEmpty(t, st.RejectedReason())
}

func TestLoadFallsBackToThePreviousFile(t *testing.T) {
	cfg := newTestConfig(t)
	writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 48)
	require.NoError(t, cloudpolicytest.Write(cfg.CloudPolicyCacheDir(), cloudpolicytest.Policy(), cloudpolicytest.Header{
		Tenant:    testTenant,
		MachineID: "another-machine",
		Revision:  49,
	}))

	st := Load(cfg, testTenant)

	assert.Equal(t, recordv1.ApplyState_APPLY_STATE_REJECTED, st.State)
	assert.True(t, st.FromPrevious)
	require.NotNil(t, st.Applied)
	assert.Equal(t, uint64(48), st.Applied.Revision)
	assert.Equal(t, 1, st.BlockEntries)
	assert.Contains(t, st.RejectedReason(), "machine")
}

func TestLoadStaleCache(t *testing.T) {
	cfg := newTestConfig(t)
	writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 48)
	setFetchedAt(t, cfg.CloudPolicyCacheDir(), time.Now().Add(-8*24*time.Hour))

	st := Load(cfg, testTenant)

	assert.Equal(t, recordv1.ApplyState_APPLY_STATE_STALE, st.State)
	assert.Equal(t, 1, st.BlockEntries, "a stale cache still applies")
	assert.Greater(t, st.CacheAge(time.Now()), StaleAfter)
}

// setFetchedAt moves fetched_at of state.json, as a cache that no fetch
// reached for a while has it.
func setFetchedAt(t *testing.T, dir string, at time.Time) {
	t.Helper()
	path := filepath.Join(dir, "state.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var state configsync.State
	require.NoError(t, json.Unmarshal(data, &state))
	state.FetchedAt = at
	data, err = json.Marshal(state)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func TestLoadReportsDroppedRules(t *testing.T) {
	cfg := newTestConfig(t)
	writeCache(t, cfg, cloudpolicytest.Policy(
		blockEvil(),
		cloudpolicytest.Trust("r_a41", "pkg:npm/x", "", time.Now().Add(time.Hour), corev1.TrustScope(99)),
		cloudpolicytest.Block("r_b1", "pkg:unknowntype/x", "", "x"),
	), 48)

	st := Load(cfg, testTenant)

	exceptions := st.Exceptions()
	var details []string
	for _, e := range exceptions {
		assert.Equal(t, PathPackageRules, e.GetPath())
		details = append(details, e.GetDetail())
		assert.Equal(t, recordv1.FieldExceptionReason_FIELD_EXCEPTION_REASON_DROPPED_RULE, e.GetReason())
	}
	require.Len(t, exceptions, 2, "details: %v", details)
	assert.Contains(t, details[0]+details[1], "r_a41")
	assert.Contains(t, details[0]+details[1], "r_b1")
	assert.Equal(t, 1, st.BlockEntries)
	assert.Zero(t, st.TrustEntries)
}

func TestApplyCooldown(t *testing.T) {
	cfg := newTestConfig(t)
	writeCache(t, cfg, cloudpolicytest.WithCooldown(cloudpolicytest.Policy(), 72*time.Hour), 48)

	st := Load(cfg, testTenant)
	target := cfg.Config
	target.DependencyCooldown = config.DependencyCooldownConfig{Enabled: false, Days: 1}
	Apply(cfg, &target, st)

	assert.Equal(t, config.DependencyCooldownConfig{Enabled: true, Days: 3}, target.DependencyCooldown)
	assert.Equal(t, []config.CloudKey{
		{Key: keyCooldownEnabled, Path: PathMinAge, Label: "the dependency cooldown", Revision: 48},
		{Key: keyCooldownDays, Path: PathMinAge, Label: "the dependency cooldown", Revision: 48},
	}, st.Keys)
	assert.Empty(t, st.Locked)

	citation := newPolicy(st, target.DependencyCooldown).CooldownCitation()
	require.NotNil(t, citation)
	assert.Equal(t, PathMinAge, citation.GetPath())
	assert.Equal(t, recordv1.Layer_LAYER_BASE, citation.GetLayer())
	assert.Equal(t, uint64(48), citation.GetRevision())
	assert.Empty(t, citation.GetRuleId())
}

func TestApplyLeavesAnUnsetFieldAtTheLowerLayer(t *testing.T) {
	cfg := newTestConfig(t)
	writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 48)

	st := Load(cfg, testTenant)
	target := cfg.Config
	Apply(cfg, &target, st)

	assert.Equal(t, cfg.Config.DependencyCooldown, target.DependencyCooldown)
	assert.Empty(t, st.Keys)
	assert.Nil(t, newPolicy(st, target.DependencyCooldown).CooldownCitation())
}

func TestApplyUnderLockdownKeepsTheManagedKeys(t *testing.T) {
	cfg := newTestConfig(t)
	writeCache(t, cfg, cloudpolicytest.WithCooldown(cloudpolicytest.Policy(), 0), 48)
	st := Load(cfg, testTenant)

	// The locked config has no readable managed file, so it keeps every key.
	locked := config.LockedRuntimeConfigForTest()
	target := config.Config{DependencyCooldown: config.DependencyCooldownConfig{Enabled: true, Days: 14}}
	Apply(locked, &target, st)

	assert.Equal(t, config.DependencyCooldownConfig{Enabled: true, Days: 14}, target.DependencyCooldown,
		"a cloud min_age of zero cannot turn off the cooldown that IT locked")
	assert.Equal(t, []string{PathMinAge}, st.Locked)
	assert.Empty(t, st.Keys)

	var locks []*recordv1.FieldException
	for _, e := range st.Exceptions() {
		if e.GetReason() == recordv1.FieldExceptionReason_FIELD_EXCEPTION_REASON_LOCKED {
			locks = append(locks, e)
		}
	}
	require.Len(t, locks, 1)
	assert.Equal(t, PathMinAge, locks[0].GetPath())
}

func TestRuntimeReloadSwapsThePolicy(t *testing.T) {
	cfg := newTestConfig(t)
	rt := &Runtime{LoginTenant: noLogin}
	rt.LoadAtStart(cfg)
	rt.Publish(cfg)

	_, blocked := rt.Current().Block(npm, "evil", "1.0.0")
	assert.False(t, blocked)
	assert.Equal(t, config.DependencyCooldownConfig{Enabled: true, Days: 2}, rt.Current().Cooldown)

	writeCache(t, cfg, cloudpolicytest.WithCooldown(cloudpolicytest.Policy(blockEvil()), 5*24*time.Hour), 48)
	rt.Reload(cfg)

	_, blocked = rt.Current().Block(npm, "evil", "1.0.0")
	assert.True(t, blocked, "a new block applies with no restart")
	assert.Equal(t, config.DependencyCooldownConfig{Enabled: true, Days: 5}, rt.Current().Cooldown)
	assert.Equal(t, config.DependencyCooldownConfig{Enabled: true, Days: 2}, cfg.Config.DependencyCooldown,
		"the reload does not change the shared config")
}

func TestRuntimeLoadAtStartRecordsTheCloudKeys(t *testing.T) {
	cfg := newTestConfig(t)
	writeCache(t, cfg, cloudpolicytest.WithCooldown(cloudpolicytest.Policy(), 72*time.Hour), 48)
	t.Cleanup(func() { cfg.SetCloudKeys(nil) })

	rt := &Runtime{LoginTenant: noLogin}
	st := rt.LoadAtStart(cfg)
	rt.Publish(cfg)

	assert.Equal(t, st.Keys, cfg.CloudKeys())
	assert.Equal(t, config.DependencyCooldownConfig{Enabled: true, Days: 3}, cfg.Config.DependencyCooldown)
	assert.Equal(t, cfg.Config.DependencyCooldown, rt.Current().Cooldown)
	assert.Same(t, st, rt.Status())
}

func TestRuntimePublishWithNoLoadAppliesOnlyTheLocalRules(t *testing.T) {
	cfg := newTestConfig(t)
	writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 48)
	cfg.Config.BlockedPackages = []config.BlockedPackage{{Purl: "pkg:npm/local-evil"}}
	require.NoError(t, config.PreprocessPackageRefs(&cfg.Config))

	rt := &Runtime{}
	rt.Publish(cfg)

	assert.Nil(t, rt.Status(), "an internal command loads no cache")
	assert.Nil(t, rt.Current().Applied())
	_, blocked := rt.Current().Block(npm, "evil", "1.0.0")
	assert.False(t, blocked)
	_, blocked = rt.Current().Block(npm, "local-evil", "1.0.0")
	assert.True(t, blocked)
}

func TestLoadWithNoConfigFolderReportsNone(t *testing.T) {
	cfg := &config.RuntimeConfig{}
	cfg.Config.Cloud.Enabled = true
	cfg.Config.Cloud.Policy = true

	st := Load(cfg, testTenant)

	assert.Equal(t, recordv1.ApplyState_APPLY_STATE_NONE, st.State)
	assert.Error(t, st.LoadErr)
}

func TestCacheMovedChecksEachFolderThatTheLoadRead(t *testing.T) {
	cfg := newTestConfig(t)
	writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 48)
	st := Load(cfg, testTenant)
	assert.False(t, st.CacheMoved(), "the cache did not change")

	// Under sudo the folder of the invoking user comes first. The load saw
	// no policy there.
	invoking := filepath.Join(t.TempDir(), "cloud-policy")
	st.seen[invoking] = ""
	assert.False(t, st.CacheMoved())

	require.NoError(t, cloudpolicytest.Write(invoking, cloudpolicytest.Policy(blockEvil()), cloudpolicytest.Header{
		Tenant: testTenant, MachineID: testMachineID(t), Revision: 49,
	}))
	assert.True(t, st.CacheMoved(), "a policy in a folder that had none counts")

	st.seen[invoking] = stateDigest(invoking)
	writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 50)
	assert.True(t, st.CacheMoved(), "a new policy in the own folder counts")
}

func TestCacheMovedWithCloudPolicyOff(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Config.Cloud.Policy = false
	st := Load(cfg, testTenant)
	writeCache(t, cfg, cloudpolicytest.Policy(blockEvil()), 48)

	assert.False(t, st.CacheMoved())
}
