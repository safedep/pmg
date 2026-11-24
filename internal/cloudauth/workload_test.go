package cloudauth

import (
	"context"
	"errors"
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

// A credential that pmg fails to revoke stays valid for hours, so the
// revoke tries again on the same errors as the exchange.
func TestRevokeWorkloadCredential(t *testing.T) {
	savedTimeout, savedDelay := callTimeout, retryDelay
	callTimeout, retryDelay = 2*time.Second, 10*time.Millisecond
	t.Cleanup(func() { callTimeout, retryDelay = savedTimeout, savedDelay })

	unavailable := status.Error(codes.Unavailable, "down")
	cases := []struct {
		name        string
		stub        *cloudauthtest.Exchange
		wantRevokes int
		wantCode    codes.Code
	}{
		{name: "revoked", stub: &cloudauthtest.Exchange{}, wantRevokes: 1},
		{name: "unavailable once, then revoked", stub: &cloudauthtest.Exchange{RevokeFirstErrs: []error{unavailable}}, wantRevokes: 2},
		{name: "the first attempt hangs", stub: &cloudauthtest.Exchange{HangFirstRevoke: 1}, wantRevokes: 2},
		{name: "unavailable twice", stub: &cloudauthtest.Exchange{RevokeErr: unavailable}, wantRevokes: 2, wantCode: codes.Unavailable},
		{name: "every attempt hangs", stub: &cloudauthtest.Exchange{Hang: true}, wantRevokes: 2, wantCode: codes.DeadlineExceeded},
		{name: "permission denied is not tried again", stub: &cloudauthtest.Exchange{RevokeErr: status.Error(codes.PermissionDenied, "denied")}, wantRevokes: 1, wantCode: codes.PermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			startStubExchange(t, tc.stub)

			start := time.Now()
			err := RevokeWorkloadCredential(context.Background(), testCredential)

			assert.Less(t, time.Since(start), callTimeout+time.Second, "the retry stays within callTimeout")
			assert.Equal(t, tc.wantCode, status.Code(err))
			require.Len(t, tc.stub.Revokes(), tc.wantRevokes)
			for _, req := range tc.stub.Revokes() {
				assert.Equal(t, testCredential.AccessToken, req.GetAccessToken())
				assert.Equal(t, testTenant, req.GetTenantDomain())
			}
			assert.Empty(t, tc.stub.Authorization(), "the revoke is keyless")
		})
	}
}

var testCredential = cloud.WorkloadCredential{
	AccessToken:  "workload-access-token",
	TenantDomain: testTenant,
	CredentialID: "wic_1",
	ExpiresAt:    time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC),
}

func TestExchangeEndsAtTheTimeout(t *testing.T) {
	saved := callTimeout
	callTimeout = 200 * time.Millisecond
	t.Cleanup(func() { callTimeout = saved })

	stub := &cloudauthtest.Exchange{Hang: true}
	startStubExchange(t, stub)

	start := time.Now()
	_, err := ExchangeWorkloadIdentity(context.Background(), testTenant)
	assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
	assert.Less(t, time.Since(start), 5*time.Second)
}

// A first attempt that runs out of its part of callTimeout leaves the other
// part, so pmg tries again in that time. The server gets the attempt
// deadline too, and can answer DeadlineExceeded before the deadline of the
// client passes.
func TestExchangeRetriesAfterAnAttemptTimesOut(t *testing.T) {
	savedTimeout, savedDelay := callTimeout, retryDelay
	callTimeout, retryDelay = 2*time.Second, 10*time.Millisecond
	t.Cleanup(func() { callTimeout, retryDelay = savedTimeout, savedDelay })

	tests := []struct {
		name      string
		stub      *cloudauthtest.Exchange
		exchanges int
	}{
		{
			name:      "the first attempt hangs",
			stub:      &cloudauthtest.Exchange{HangFirst: 1},
			exchanges: 1,
		},
		{
			name: "the server answers DeadlineExceeded",
			stub: &cloudauthtest.Exchange{FirstErrs: []error{
				status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
			}},
			exchanges: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startStubExchange(t, tt.stub)

			cred, err := ExchangeWorkloadIdentity(context.Background(), testTenant)
			require.NoError(t, err)
			assert.Equal(t, cloudauthtest.CredentialID, cred.CredentialID)
			assert.Len(t, tt.stub.Exchanges(), tt.exchanges)
		})
	}
}

func TestResolveCredentialsFromCredentialFile(t *testing.T) {
	t.Setenv("SAFEDEP_API_KEY", "env-api-key")
	t.Setenv("SAFEDEP_TENANT_ID", "other.safedep.io")

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
