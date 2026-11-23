package cloudauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	messagesv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	"github.com/safedep/dry/cloud"
	"github.com/safedep/pmg/internal/cloudauth/cloudauthtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testTenant = "acme.safedep.io"

func startStubExchange(t *testing.T, stub *cloudauthtest.Exchange) {
	for name, value := range cloudauthtest.Start(t, stub) {
		t.Setenv(name, value)
	}
}

func TestExchangeWorkloadIdentity(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantRefused bool
		wantErr     bool
	}{
		{name: "issued"},
		{name: "no matching rule", err: status.Error(codes.PermissionDenied, "no rule"), wantRefused: true, wantErr: true},
		{name: "tenant cap", err: status.Error(codes.ResourceExhausted, "cap"), wantRefused: true, wantErr: true},
		{name: "no usable provider", err: status.Error(codes.FailedPrecondition, "no provider"), wantRefused: true, wantErr: true},
		{name: "server unavailable", err: status.Error(codes.Unavailable, "down"), wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &cloudauthtest.Exchange{Err: tc.err}
			startStubExchange(t, stub)

			cred, err := ExchangeWorkloadIdentity(context.Background(), testTenant)

			require.Len(t, stub.Exchanges(), 1)
			req := stub.Exchanges()[0]
			assert.False(t, req.HasRequestedLifetime(), "the proxy cannot refresh, so pmg asks for the rule maximum")
			assert.Equal(t, messagesv1.CredentialGrant_CREDENTIAL_GRANT_TOOL, req.GetRequestedGrant())
			assert.Equal(t, testTenant, req.GetTenantDomain())
			assert.Equal(t, cloudauthtest.IDToken, req.GetSubjectToken())
			assert.Equal(t, "pmg", req.GetToolName())
			assert.Empty(t, stub.Authorization(), "the exchange is keyless")

			assert.Equal(t, tc.wantRefused, errors.Is(err, ErrExchangeRefused))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, cloudauthtest.AccessToken, cred.AccessToken)
			assert.Equal(t, testTenant, cred.TenantDomain)
			assert.Equal(t, cloudauthtest.EndpointID, cred.EndpointID)
		})
	}
}

func TestExchangeWorkloadIdentityWithoutIDToken(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	startStubExchange(t, stub)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	_, err := ExchangeWorkloadIdentity(context.Background(), testTenant)

	require.ErrorIs(t, err, cloud.ErrNoWorkloadIdentity)
	assert.Empty(t, stub.Exchanges())
}

func TestRevokeWorkloadCredential(t *testing.T) {
	stub := &cloudauthtest.Exchange{}
	startStubExchange(t, stub)

	err := RevokeWorkloadCredential(context.Background(), cloud.WorkloadCredential{
		AccessToken:  "workload-access-token",
		TenantDomain: testTenant,
	})

	require.NoError(t, err)
	require.Len(t, stub.Revokes(), 1)
	assert.Equal(t, "workload-access-token", stub.Revokes()[0].GetAccessToken())
	assert.Equal(t, testTenant, stub.Revokes()[0].GetTenantDomain())
	assert.Empty(t, stub.Authorization(), "the revoke is keyless")
}

func TestCredentialFile(t *testing.T) {
	cred := cloud.WorkloadCredential{
		AccessToken:  "workload-access-token",
		TenantDomain: testTenant,
		CredentialID: "wic_1",
		ExpiresAt:    time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC),
	}

	t.Run("round trip in a file that only the owner can read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, WriteCredentialFile(path, cred))

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

		got, err := ReadCredentialFile(path)
		require.NoError(t, err)
		assert.Equal(t, cred, got)
	})

	t.Run("write refuses a file that exists", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		assert.Error(t, WriteCredentialFile(path, cred))
	})

	t.Run("read refuses a file that other users can read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, WriteCredentialFile(path, cred))
		require.NoError(t, os.Chmod(path, 0o644))
		_, err := ReadCredentialFile(path)
		assert.ErrorContains(t, err, "other users must have no access")
	})

	t.Run("read refuses a file of another user", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("only root can give a file to another user")
		}
		path := filepath.Join(t.TempDir(), "cred.json")
		require.NoError(t, WriteCredentialFile(path, cred))
		require.NoError(t, os.Chown(path, 65534, 65534))
		_, err := ReadCredentialFile(path)
		assert.ErrorContains(t, err, "belongs to uid 65534")
	})
}

func TestResolveCredentialsFromCredentialFile(t *testing.T) {
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

	t.Run("a missing file fails and does not fall back", func(t *testing.T) {
		t.Setenv(CredentialFileEnv, filepath.Join(t.TempDir(), "missing.json"))

		_, closeFn, err := ResolveCredentials()
		require.NoError(t, closeFn())
		assert.ErrorContains(t, err, CredentialFileEnv)
	})
}
