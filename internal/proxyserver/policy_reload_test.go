package proxyserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/cloud/configsync"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudpolicy"
	cpt "github.com/safedep/pmg/internal/cloudpolicy/cloudpolicytest"
	"github.com/safedep/pmg/internal/cloudsync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const reloadEndpointID = "proxyserver-reload-test"

func writeReloadCache(t *testing.T, cfg *config.RuntimeConfig, revision uint64, purl string) string {
	t.Helper()
	machineID, err := cpt.MachineID(reloadEndpointID)
	require.NoError(t, err)
	require.NoError(t, cpt.Write(cfg.CloudPolicyCacheDir(), cpt.Policy(cpt.Block("r_block", purl, "", "incident")),
		cpt.Header{Tenant: "acme.safedep.io", MachineID: machineID, Revision: revision}))

	store, err := configsync.NewStore(cfg.CloudPolicyCacheDir())
	require.NoError(t, err)
	state, err := store.State()
	require.NoError(t, err)
	return state.Digest
}

func newReloadConfig(t *testing.T) *config.RuntimeConfig {
	t.Helper()
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	config.Reload()
	t.Cleanup(config.Reload)
	cfg := config.Get()
	cfg.Config.Cloud.Enabled = true
	cfg.Config.Cloud.Policy = true
	cfg.Config.Cloud.EndpointID = reloadEndpointID
	return cfg
}

func TestReloadIfCacheMoved(t *testing.T) {
	cfg := newReloadConfig(t)
	digest48 := writeReloadCache(t, cfg, 48, "pkg:npm/first")
	rt := &cloudpolicy.Runtime{LoginTenant: func() string { return "" }}
	rt.LoadAtStartForTenant(cfg, "")
	rt.Publish(cfg)
	require.Equal(t, digest48, rt.Current().Applied().Digest)

	var out bytes.Buffer
	assert.False(t, reloadIfCacheMoved(cfg, rt, &out), "the daemon applies the cache already")
	assert.Empty(t, out.String())

	// Another pmg process commits revision 49 and reports it on check-in.
	// The daemon applies it at its next tick, with no fetch of its own.
	writeReloadCache(t, cfg, 49, "pkg:npm/second")
	assert.True(t, reloadIfCacheMoved(cfg, rt, &out))
	assert.Equal(t, "Applied cloud policy revision 49\n", out.String())

	require.NotNil(t, rt.Current().Applied())
	assert.Equal(t, uint64(49), rt.Current().Applied().Revision)
	_, blocked := rt.Current().Block(packagev1.Ecosystem_ECOSYSTEM_NPM, "second", "1.0.0")
	assert.True(t, blocked, "the daemon applies the policy that another process fetched")

	out.Reset()
	assert.False(t, reloadIfCacheMoved(cfg, rt, &out), "the next tick does not load the same cache again")
	assert.Empty(t, out.String(), "the next tick writes no line")

	// Revision 50 names another machine, so it fails its check and
	// revision 49 still applies.
	require.NoError(t, cpt.Write(cfg.CloudPolicyCacheDir(), cpt.Policy(cpt.Block("r_block", "pkg:npm/third", "", "incident")),
		cpt.Header{Tenant: "acme.safedep.io", MachineID: "another-machine", Revision: 50}))
	assert.True(t, reloadIfCacheMoved(cfg, rt, &out))
	assert.Equal(t, "Rejected cloud policy revision 50. Revision 49 still applies\n", out.String())
	assert.Equal(t, uint64(49), rt.Current().Applied().Revision)
}

func TestReloadIfCacheMovedWithCloudPolicyOff(t *testing.T) {
	cfg := newReloadConfig(t)
	cfg.Config.Cloud.Policy = false
	writeReloadCache(t, cfg, 48, "pkg:npm/first")
	rt := &cloudpolicy.Runtime{LoginTenant: func() string { return "" }}
	rt.LoadAtStartForTenant(cfg, "")
	rt.Publish(cfg)

	assert.False(t, reloadIfCacheMoved(cfg, rt, io.Discard), "pmg reads no cache with cloud.policy off")
}

func TestFetchPolicyAtStart(t *testing.T) {
	tests := []struct {
		name        string
		policyOff   bool
		cached      bool
		fetch       func(t *testing.T, cfg *config.RuntimeConfig) (*cloudsync.Result, error)
		wantCalled  bool
		wantWarning string
		wantApplied uint64
	}{
		{
			name: "no cache fetches before the proxy starts",
			fetch: func(t *testing.T, cfg *config.RuntimeConfig) (*cloudsync.Result, error) {
				writeReloadCache(t, cfg, 7, "pkg:npm/first")
				return &cloudsync.Result{PolicyRan: true}, nil
			},
			wantCalled:  true,
			wantApplied: 7,
		},
		{
			name: "a sync error returns a warning",
			fetch: func(*testing.T, *config.RuntimeConfig) (*cloudsync.Result, error) {
				return nil, errors.New("no network")
			},
			wantCalled:  true,
			wantWarning: "PMG cannot fetch the cloud policy (no network). No cloud policy applies until the next fetch.",
		},
		{
			name: "a policy fetch error returns a warning",
			fetch: func(*testing.T, *config.RuntimeConfig) (*cloudsync.Result, error) {
				return &cloudsync.Result{PolicyRan: true, PolicyErr: errors.New("unauthenticated")}, nil
			},
			wantCalled:  true,
			wantWarning: "PMG cannot fetch the cloud policy (unauthenticated). No cloud policy applies until the next fetch.",
		},
		{
			name: "a policy that another process commits during a failed fetch gives no warning",
			fetch: func(t *testing.T, cfg *config.RuntimeConfig) (*cloudsync.Result, error) {
				writeReloadCache(t, cfg, 9, "pkg:npm/first")
				return nil, errors.New("lock busy")
			},
			wantCalled:  true,
			wantApplied: 9,
		},
		{
			name:        "a cache serves at once",
			cached:      true,
			wantApplied: 48,
		},
		{
			name:      "cloud policy off makes no fetch",
			policyOff: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newReloadConfig(t)
			cfg.Config.Cloud.Policy = !tc.policyOff
			if tc.cached {
				writeReloadCache(t, cfg, 48, "pkg:npm/first")
			}
			rt := &cloudpolicy.Runtime{LoginTenant: func() string { return "" }}
			rt.LoadAtStartForTenant(cfg, "")
			rt.Publish(cfg)

			called := false
			sync := func(_ context.Context, cfg *config.RuntimeConfig, plan cloudsync.Plan) (*cloudsync.Result, error) {
				called = true
				assert.Equal(t, cloudsync.StepForce, plan.Policy)
				assert.Equal(t, cloudsync.StepOff, plan.Events, "the first fetch sends no events")
				return tc.fetch(t, cfg)
			}

			warning := fetchPolicyAtStart(context.Background(), cfg, rt, sync, io.Discard)
			assert.Equal(t, tc.wantCalled, called)
			assert.Equal(t, tc.wantWarning, warning)
			if tc.wantApplied == 0 {
				assert.Nil(t, rt.Current().Applied())
				return
			}
			require.NotNil(t, rt.Current().Applied())
			assert.Equal(t, tc.wantApplied, rt.Current().Applied().Revision)
		})
	}
}
