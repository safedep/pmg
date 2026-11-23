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
	unavailable := status.Error(codes.Unavailable, "down")
	cases := []struct {
		name          string
		firstErrs     []error
		err           error
		wantExchanges int
		wantRefused   bool
		wantErr       bool
	}{
		{name: "issued", wantExchanges: 1},
		{name: "no matching rule", err: status.Error(codes.PermissionDenied, "no rule"), wantExchanges: 1, wantRefused: true, wantErr: true},
		{name: "tenant cap", err: status.Error(codes.ResourceExhausted, "cap"), wantExchanges: 1, wantRefused: true, wantErr: true},
		{name: "no usable provider", err: status.Error(codes.FailedPrecondition, "no provider"), wantExchanges: 1, wantRefused: true, wantErr: true},
		{name: "unavailable once, then issued", firstErrs: []error{unavailable}, wantExchanges: 2},
		{name: "unavailable twice", err: unavailable, wantExchanges: 2, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &cloudauthtest.Exchange{FirstErrs: tc.firstErrs, Err: tc.err}
			startStubExchange(t, stub)

			cred, err := ExchangeWorkloadIdentity(context.Background(), testTenant)

			require.Len(t, stub.Exchanges(), tc.wantExchanges)
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

var testCredential = cloud.WorkloadCredential{
	AccessToken:  "workload-access-token",
	TenantDomain: testTenant,
	CredentialID: "wic_1",
	ExpiresAt:    time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC),
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
	stub := &cloudauthtest.Exchange{}
	startStubExchange(t, stub)

	_, err := ExchangeToFile(context.Background(), testTenant, filepath.Join(t.TempDir(), "missing", "cred.json"))

	require.ErrorIs(t, err, ErrCredentialFileWrite)
	require.Len(t, stub.Revokes(), 1, "no caller holds the credential, so pmg revokes it")
	assert.Equal(t, cloudauthtest.AccessToken, stub.Revokes()[0].GetAccessToken())
}

func TestCallsEndAtTheTimeout(t *testing.T) {
	saved := callTimeout
	callTimeout = 200 * time.Millisecond
	t.Cleanup(func() { callTimeout = saved })

	stub := &cloudauthtest.Exchange{Hang: true}
	startStubExchange(t, stub)

	t.Run("exchange", func(t *testing.T) {
		start := time.Now()
		_, err := ExchangeWorkloadIdentity(context.Background(), testTenant)
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
		assert.Less(t, time.Since(start), 5*time.Second)
	})

	t.Run("revoke", func(t *testing.T) {
		start := time.Now()
		err := RevokeWorkloadCredential(context.Background(), testCredential)
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
		assert.Less(t, time.Since(start), 5*time.Second)
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

	t.Run("an empty value is unset", func(t *testing.T) {
		t.Setenv(CredentialFileEnv, "")

		creds, closeFn, err := ResolveCredentials()
		require.NoError(t, err)
		require.NoError(t, closeFn())
		tenant, err := creds.GetTenantDomain()
		require.NoError(t, err)
		assert.NotEqual(t, testTenant, tenant)
	})

	t.Run("a missing file fails and does not fall back", func(t *testing.T) {
		t.Setenv(CredentialFileEnv, filepath.Join(t.TempDir(), "missing.json"))

		_, closeFn, err := ResolveCredentials()
		require.NoError(t, closeFn())
		assert.ErrorContains(t, err, CredentialFileEnv)
	})
}
