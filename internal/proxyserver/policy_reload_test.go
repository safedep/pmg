package proxyserver

import (
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

func TestReloadIfCacheMoved(t *testing.T) {
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	config.Reload()
	t.Cleanup(config.Reload)
	cfg := config.Get()
	cfg.Config.Cloud.Enabled = true
	cfg.Config.Cloud.Policy = true
	cfg.Config.Cloud.EndpointID = reloadEndpointID

	digest48 := writeReloadCache(t, cfg, 48, "pkg:npm/first")
	rt := &cloudpolicy.Runtime{}
	rt.LoadAtStartForTenant(cfg, "")
	rt.Publish(cfg)
	require.Equal(t, digest48, rt.Current().Applied().Digest)

	notModified := func(digest string, revision uint64) *cloudsync.Result {
		return &cloudsync.Result{PolicyRan: true, Policy: &configsync.FetchResult{
			Status: configsync.FetchNotModified, Digest: digest, Revision: revision,
		}}
	}

	assert.False(t, reloadIfCacheMoved(cfg, rt, notModified(digest48, 48)), "the daemon applies the cache already")
	assert.False(t, reloadIfCacheMoved(cfg, rt, &cloudsync.Result{}), "no fetch ran")

	// Another pmg process commits revision 49. The fetch of the daemon sends
	// the digest of 49 and gets NOT_MODIFIED.
	digest49 := writeReloadCache(t, cfg, 49, "pkg:npm/second")
	assert.True(t, reloadIfCacheMoved(cfg, rt, notModified(digest49, 49)))

	assert.Equal(t, uint64(49), rt.Current().Applied().Revision)
	_, blocked := rt.Current().Block(packagev1.Ecosystem_ECOSYSTEM_NPM, "second", "1.0.0")
	assert.True(t, blocked, "the daemon applies the policy that another process fetched")
}
