package cloudauth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/keychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memKeychain keeps the secrets in memory, so a test does not write to the
// keychain of the host.
type memKeychain map[string]string

func (m memKeychain) Get(_ context.Context, key string) (*keychain.Secret, error) {
	value, ok := m[key]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	return &keychain.Secret{Value: value}, nil
}

func (m memKeychain) Set(_ context.Context, key string, secret *keychain.Secret) error {
	m[key] = secret.Value
	return nil
}

func (m memKeychain) Delete(_ context.Context, key string) error {
	delete(m, key)
	return nil
}

func (m memKeychain) Close() error { return nil }

// keychainKey saves an API key the way the keychain stores it and resolves it
// the way pmg reads it. A zero expiresAt saves a key with no recorded expiry,
// as pmg cloud login does.
func keychainKey(t *testing.T, expiresAt time.Time) *cloud.Credentials {
	t.Helper()
	opts := []cloud.KeychainOption{cloud.WithKeychainHandle(memKeychain{})}

	store, err := cloud.NewKeychainCredentialStore(opts...)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	if expiresAt.IsZero() {
		require.NoError(t, store.SaveAPIKeyCredential("sk-test", "acme.safedep.io"))
	} else {
		require.NoError(t, store.SaveAPIKeyCredentialWithMetadata("sk-test", "acme.safedep.io",
			cloud.APIKeyMetadata{KeyID: "key-1", ExpiresAt: expiresAt}))
	}

	resolver, err := cloud.NewKeychainCredentialResolver(cloud.CredentialTypeAPIKey, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, resolver.Close()) })

	creds, err := resolver.Resolve()
	require.NoError(t, err)
	return creds
}

func TestStatusOfKeychainKey(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		expiresAt time.Time
		want      KeyState
	}{
		{name: "expired", expiresAt: now.Add(-time.Hour), want: KeyStateExpired},
		{name: "expires now", expiresAt: now, want: KeyStateExpired},
		{name: "expires inside the warning window", expiresAt: now.Add(3 * 24 * time.Hour), want: KeyStateExpiring},
		{name: "expires at the end of the warning window", expiresAt: now.Add(KeyExpiryWarning), want: KeyStateValid},
		{name: "valid", expiresAt: now.Add(60 * 24 * time.Hour), want: KeyStateValid},
		{name: "no recorded expiry", want: KeyStateUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := StatusOf(keychainKey(t, tt.expiresAt), now)

			assert.Equal(t, KeyOriginKeychain, status.Origin)
			assert.Equal(t, tt.want, status.State)
			assert.True(t, tt.expiresAt.Equal(status.ExpiresAt))
		})
	}
}

func TestStatusOfOrigin(t *testing.T) {
	t.Run("environment", func(t *testing.T) {
		t.Setenv("SAFEDEP_API_KEY", "sk-env")
		t.Setenv("SAFEDEP_TENANT_ID", "acme.safedep.io")
		resolver, err := cloud.NewEnvCredentialResolver()
		require.NoError(t, err)
		creds, err := resolver.Resolve()
		require.NoError(t, err)

		status := StatusOf(creds, time.Now())
		assert.Equal(t, KeyOriginEnvironment, status.Origin)
		assert.Equal(t, KeyStateUnknown, status.State)
	})

	t.Run("credential file", func(t *testing.T) {
		t.Setenv(CredentialFileEnv, t.TempDir()+"/credential.json")
		creds, err := cloud.NewAPIKeyCredential("access-token", "acme.safedep.io")
		require.NoError(t, err)

		assert.Equal(t, KeyOriginCredentialFile, StatusOf(creds, time.Now()).Origin)
	})
}

func TestResolveStatusWithACredentialFileThatPmgCannotUse(t *testing.T) {
	t.Setenv(CredentialFileEnv, filepath.Join(t.TempDir(), "missing.json"))

	status, err := ResolveStatus(time.Now())

	require.Error(t, err)
	assert.Equal(t, KeyOriginCredentialFile, status.Origin)
}
