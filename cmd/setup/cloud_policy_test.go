package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/core/v1"
	specv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/spec/v1"
	"github.com/safedep/dry/cloud/configsync"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudpolicy"
	cpt "github.com/safedep/pmg/internal/cloudpolicy/cloudpolicytest"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	doctorTenant     = "platform-eng.acme.safedep.io"
	doctorEndpointID = "doctor-test"
)

func newCloudPolicyConfig(t *testing.T) *config.RuntimeConfig {
	t.Helper()
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	config.Reload()
	t.Cleanup(config.Reload)

	cfg := config.Get()
	cfg.Config.Cloud.Enabled = true
	cfg.Config.Cloud.Policy = true
	cfg.Config.Cloud.EndpointID = doctorEndpointID
	return cfg
}

func writeDoctorCache(t *testing.T, cfg *config.RuntimeConfig, policy *specv1.ResolvedPolicy, revision uint64, machineID string) {
	t.Helper()
	if machineID == "" {
		var err error
		machineID, err = cpt.MachineID(doctorEndpointID)
		require.NoError(t, err)
	}
	require.NoError(t, cpt.Write(cfg.CloudPolicyCacheDir(), policy, cpt.Header{
		Tenant: doctorTenant, MachineID: machineID, Revision: revision, DefaultPolicyRevision: 12,
	}))
}

// ageCache moves fetched_at of the cache back by age.
func ageCache(t *testing.T, cfg *config.RuntimeConfig, age time.Duration) {
	t.Helper()
	path := filepath.Join(cfg.CloudPolicyCacheDir(), "state.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var state configsync.State
	require.NoError(t, json.Unmarshal(data, &state))
	state.FetchedAt = state.FetchedAt.Add(-age)
	data, err = json.Marshal(state)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

type doctorLine struct {
	status  doctor.CheckStatus
	message string
}

func TestCloudPolicyResults(t *testing.T) {
	expires := time.Now().Add(24 * time.Hour)
	block := cpt.Block("r_9c1", "pkg:npm/evil", "", "incident")

	tests := []struct {
		name  string
		setup func(t *testing.T, cfg *config.RuntimeConfig)
		want  []doctorLine

		// wantInLast is more text that the last line holds.
		wantInLast string
	}{
		{
			name:  "cloud.policy off runs no check",
			setup: func(t *testing.T, cfg *config.RuntimeConfig) { cfg.Config.Cloud.Policy = false },
		},
		{
			name:  "cloud.policy on and cloud.enabled off runs no check",
			setup: func(t *testing.T, cfg *config.RuntimeConfig) { cfg.Config.Cloud.Enabled = false },
		},
		{
			name:  "no cache warns",
			setup: func(t *testing.T, cfg *config.RuntimeConfig) {},
			want: []doctorLine{{doctor.StatusWarn,
				"cloud policy is on, but no policy cache exists. pmg fetches it after the next command"}},
		},
		{
			name: "an applied cache passes",
			setup: func(t *testing.T, cfg *config.RuntimeConfig) {
				writeDoctorCache(t, cfg, cpt.Policy(block), 52, "")
				ageCache(t, cfg, 12*time.Minute)
			},
			want: []doctorLine{{doctor.StatusPass,
				"on · revision 52 applied · cache 12m old · tenant " + doctorTenant}},
		},
		{
			name: "an old cache warns",
			setup: func(t *testing.T, cfg *config.RuntimeConfig) {
				writeDoctorCache(t, cfg, cpt.Policy(block), 52, "")
				ageCache(t, cfg, 9*24*time.Hour)
			},
			want: []doctorLine{
				{doctor.StatusWarn, "on · revision 52 applied · cache 9d old · tenant " + doctorTenant},
				{doctor.StatusWarn, "the policy cache is 9d old. The last policy still applies"},
			},
		},
		{
			name: "a current file that fails its check warns",
			setup: func(t *testing.T, cfg *config.RuntimeConfig) {
				writeDoctorCache(t, cfg, cpt.Policy(block), 52, "")
				writeDoctorCache(t, cfg, cpt.Policy(), 53, "another-machine")
			},
			want: []doctorLine{
				{doctor.StatusWarn, "on · revision 52 applied"},
				{doctor.StatusWarn, "revision 53 failed its check"},
			},
		},
		{
			name: "dropped trust entries warn with their ids",
			setup: func(t *testing.T, cfg *config.RuntimeConfig) {
				writeDoctorCache(t, cfg, cpt.Policy(
					cpt.Trust("r_a41", "pkg:npm/a", "", expires, corev1.TrustScope(99)),
					cpt.Trust("r_b07", "pkg:npm/b", "", expires, corev1.TrustScope(98)),
				), 52, "")
			},
			want: []doctorLine{
				{doctor.StatusWarn, "on · revision 52 applied"},
				{doctor.StatusWarn, "2 trust entries dropped ("},
			},
			wantInLast: "r_a41, r_b07",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newCloudPolicyConfig(t)
			tt.setup(t, cfg)

			st := cloudpolicy.Load(cfg, doctorTenant)
			results := cloudPolicyResults(st, time.Now())

			require.Len(t, results, len(tt.want))
			for i, want := range tt.want {
				assert.Equal(t, want.status, results[i].Status, results[i].Message)
				assert.Contains(t, results[i].Message, want.message)
			}
			if tt.wantInLast != "" {
				assert.Contains(t, results[len(results)-1].Message, tt.wantInLast)
			}
		})
	}
}

func TestCloudPolicyResultsOfTheTemplateConfig(t *testing.T) {
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	t.Setenv("PMG_CLOUD_ENABLED", "")
	t.Setenv("PMG_CLOUD_POLICY", "")
	config.Reload()
	t.Cleanup(config.Reload)
	require.NoError(t, config.WriteTemplateConfig())
	config.Reload()

	cfg := config.Get()
	require.FileExists(t, cfg.ConfigFilePath())

	assert.Empty(t, cloudPolicyResults(cloudpolicy.Load(cfg, ""), time.Now()))
}

func TestCloudPolicySummaryKeepsTheRevisionInTheTable(t *testing.T) {
	const tenant = "platform-engineering-and-developer-productivity.acme-corporation.safedep.io"
	cfg := newCloudPolicyConfig(t)
	machineID, err := cpt.MachineID(doctorEndpointID)
	require.NoError(t, err)
	require.NoError(t, cpt.Write(cfg.CloudPolicyCacheDir(), cpt.Policy(), cpt.Header{
		Tenant: tenant, MachineID: machineID, Revision: 52, DefaultPolicyRevision: 12,
	}))
	ageCache(t, cfg, 12*time.Minute)
	st := cloudpolicy.Load(cfg, tenant)
	require.NotNil(t, st.Applied)

	shown := ui.Truncate(cloudPolicySummary(st, time.Now()), doctorSummaryWidth)

	assert.Contains(t, shown, "revision 52 applied")
	assert.Contains(t, shown, "cache 12m old")
}

func TestCollectCloudPolicyInfo(t *testing.T) {
	cfg := newCloudPolicyConfig(t)
	writeDoctorCache(t, cfg, cpt.WithCooldown(cpt.Policy(cpt.Block("r_9c1", "pkg:npm/evil", "", "incident")), 72*time.Hour), 52, "")
	st := cloudpolicy.Load(cfg, doctorTenant)
	cloudpolicy.Apply(cfg, &config.Config{}, st)

	info := collectCloudPolicyInfo(st)

	assert.True(t, info.Enabled)
	assert.Equal(t, "applied", info.State)
	assert.Equal(t, doctorTenant, info.Tenant)
	assert.Equal(t, uint64(52), info.Revision)
	assert.Equal(t, uint64(12), info.DefaultPolicyRevision)
	assert.Equal(t, st.Applied.Digest, info.Digest)
	assert.NotEmpty(t, info.FetchedAt)
	assert.NotEmpty(t, info.StoredAt)
	assert.Equal(t, cfg.CloudPolicyCacheDir(), info.CacheDir)
	assert.Equal(t, 1, info.BlockEntries)
	assert.Equal(t, []cloudPolicyKey{
		{Key: "dependency_cooldown.enabled", Path: cloudpolicy.PathMinAge},
		{Key: "dependency_cooldown.days", Path: cloudpolicy.PathMinAge},
	}, info.Keys)

	cfg.Config.Cloud.Policy = false
	disabled := collectCloudPolicyInfo(cloudpolicy.Load(cfg, doctorTenant))
	assert.False(t, disabled.Enabled)
	assert.Equal(t, "disabled", disabled.State)
	assert.Zero(t, disabled.Revision)
}

func TestFormatAge(t *testing.T) {
	tests := []struct {
		age  time.Duration
		want string
	}{
		{12 * time.Minute, "12m"},
		{3 * time.Hour, "3h"},
		{47 * time.Hour, "47h"},
		{9 * 24 * time.Hour, "9d"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, formatAge(tt.age))
	}
}
