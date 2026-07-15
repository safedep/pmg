package cloudauth

import (
	"testing"

	"github.com/safedep/dry/cloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKeychainOptions(t *testing.T) []cloud.KeychainOption {
	t.Helper()
	return []cloud.KeychainOption{
		cloud.WithAppName("safedep-test-" + t.Name()),
		cloud.WithInsecureFileFallbackPath(t.TempDir() + "/creds.json"),
	}
}

func TestResolveCredentialsFromKeychainStore(t *testing.T) {
	t.Setenv("SAFEDEP_API_KEY", "")
	t.Setenv("SAFEDEP_TENANT_ID", "")

	opts := testKeychainOptions(t)

	store, err := cloud.NewKeychainCredentialStore(opts...)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, store.Clear())
		require.NoError(t, store.Close())
	})

	require.NoError(t, store.SaveAPIKeyCredential("sk-test-key", "tenant-123"))

	creds, closeFn, err := ResolveCredentials(opts...)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closeFn()) })

	apiKey, err := creds.GetAPIKey()
	require.NoError(t, err)
	assert.Equal(t, "sk-test-key", apiKey)

	tenant, err := creds.GetTenantDomain()
	require.NoError(t, err)
	assert.Equal(t, "tenant-123", tenant)
}

func TestResolveCredentialsFallsBackToEnv(t *testing.T) {
	t.Setenv("SAFEDEP_API_KEY", "env-key")
	t.Setenv("SAFEDEP_TENANT_ID", "env-tenant")

	creds, closeFn, err := ResolveCredentials(testKeychainOptions(t)...)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closeFn()) })

	apiKey, err := creds.GetAPIKey()
	require.NoError(t, err)
	assert.Equal(t, "env-key", apiKey)

	tenant, err := creds.GetTenantDomain()
	require.NoError(t, err)
	assert.Equal(t, "env-tenant", tenant)
}

func TestResolveCredentialsNoCredentials(t *testing.T) {
	t.Setenv("SAFEDEP_API_KEY", "")
	t.Setenv("SAFEDEP_TENANT_ID", "")

	_, closeFn, err := ResolveCredentials(testKeychainOptions(t)...)
	require.Error(t, err)
	require.NoError(t, closeFn())
}
