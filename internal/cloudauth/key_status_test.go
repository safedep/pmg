package cloudauth

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/pmg/internal/cloudauth/cloudauthtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			status := StatusOf(cloudauthtest.KeychainKey(t, tt.expiresAt), now)

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
