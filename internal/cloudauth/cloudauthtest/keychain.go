package cloudauthtest

import (
	"context"
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

// KeychainKey saves an API key the way the keychain stores it and resolves it
// the way pmg reads it, in an in-memory keychain. A zero expiresAt saves a key
// with no recorded expiry, as pmg cloud login does.
func KeychainKey(t *testing.T, expiresAt time.Time) *cloud.Credentials {
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
