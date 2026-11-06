package proxyserver

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/cloud/configsync"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudpolicy"
	cpt "github.com/safedep/pmg/internal/cloudpolicy/cloudpolicytest"
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

	assert.False(t, reloadIfCacheMoved(cfg, rt), "the daemon applies the cache already")

	// Another pmg process commits revision 49 and reports it on check-in.
	// The daemon applies it at its next tick, with no fetch of its own.
	writeReloadCache(t, cfg, 49, "pkg:npm/second")
	assert.True(t, reloadIfCacheMoved(cfg, rt))

	require.NotNil(t, rt.Current().Applied())
	assert.Equal(t, uint64(49), rt.Current().Applied().Revision)
	_, blocked := rt.Current().Block(packagev1.Ecosystem_ECOSYSTEM_NPM, "second", "1.0.0")
	assert.True(t, blocked, "the daemon applies the policy that another process fetched")

	assert.False(t, reloadIfCacheMoved(cfg, rt), "the next tick does not load the same cache again")
}

func TestReloadIfCacheMovedWithCloudPolicyOff(t *testing.T) {
	cfg := newReloadConfig(t)
	cfg.Config.Cloud.Policy = false
	writeReloadCache(t, cfg, 48, "pkg:npm/first")
	rt := &cloudpolicy.Runtime{LoginTenant: func() string { return "" }}
	rt.LoadAtStartForTenant(cfg, "")
	rt.Publish(cfg)

	assert.False(t, reloadIfCacheMoved(cfg, rt), "pmg reads no cache with cloud.policy off")
}
