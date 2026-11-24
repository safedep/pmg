//go:build !windows

package cloudauth

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/pmg/internal/cloudauth/cloudauthtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// pmg refuses a credential file on Windows, so these tests run on Unix
// only. workload_windows_test.go tests the refusal.
func TestCredentialFileUnixAccess(t *testing.T) {
	t.Run("write gives the file mode 0600", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, WriteCredentialFile(path, testCredential))
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})

	t.Run("read refuses a file that other users can read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, WriteCredentialFile(path, testCredential))
		require.NoError(t, os.Chmod(path, 0o644))
		_, err := ReadCredentialFile(path)
		assert.ErrorContains(t, err, "other users must have no access")
	})

	t.Run("read refuses a file of another user", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("only root can give a file to another user")
		}
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, WriteCredentialFile(path, testCredential))
		require.NoError(t, os.Chown(path, 65534, 65534))
		_, err := ReadCredentialFile(path)
		assert.ErrorContains(t, err, "belongs to uid 65534")
	})
}

func TestCredentialFile(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, WriteCredentialFile(path, testCredential))

		got, err := ReadCredentialFile(path)
		require.NoError(t, err)
		assert.Equal(t, testCredential, got)
	})

	t.Run("write refuses a file that exists", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		assert.Error(t, WriteCredentialFile(path, testCredential))
	})
}

func TestExchangeToFileRevokesWhenTheWriteFails(t *testing.T) {
	for _, tc := range []struct {
		name        string
		revokeErr   error
		wantRevoked bool
	}{
		{name: "the revoke succeeds", wantRevoked: true},
		{name: "the revoke fails", revokeErr: status.Error(codes.Unavailable, "down")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &cloudauthtest.Exchange{RevokeErr: tc.revokeErr}
			startStubExchange(t, stub)

			_, err := ExchangeToFile(context.Background(), testTenant, filepath.Join(t.TempDir(), "missing", "cred.json"))

			require.ErrorIs(t, err, ErrCredentialFileWrite)
			var writeErr *CredentialWriteError
			require.ErrorAs(t, err, &writeErr)
			assert.Equal(t, tc.wantRevoked, writeErr.RevokeErr == nil)
			assert.False(t, writeErr.ExpiresAt.IsZero())
			require.Len(t, stub.Revokes(), 1, "no caller holds the credential, so pmg revokes it")
			assert.Equal(t, cloudauthtest.AccessToken, stub.Revokes()[0].GetAccessToken())
		})
	}
}

func TestResolveCredentialsPrefersTheCredentialFile(t *testing.T) {
	t.Setenv("SAFEDEP_API_KEY", "env-api-key")
	t.Setenv("SAFEDEP_TENANT_ID", "other.safedep.io")

	t.Run("the file takes precedence over the environment", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, WriteCredentialFile(path, cloud.WorkloadCredential{
			AccessToken:  "workload-access-token",
			TenantDomain: testTenant,
		}))
		t.Setenv(CredentialFileEnv, path)

		creds, closeFn, err := ResolveCredentials()
		require.NoError(t, err)
		require.NoError(t, closeFn())
		apiKey, err := creds.GetAPIKey()
		require.NoError(t, err)
		assert.Equal(t, "workload-access-token", apiKey)
		tenant, err := creds.GetTenantDomain()
		require.NoError(t, err)
		assert.Equal(t, testTenant, tenant)
	})
}
