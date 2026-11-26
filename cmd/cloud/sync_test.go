package cloud

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/cloudauth"
	"github.com/safedep/pmg/internal/cloudsync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

func entitlementStatusErr(t *testing.T, anyNesting int) error {
	t.Helper()

	detail, err := anypb.New(&errdetails.ErrorInfo{
		Reason: "entitlement_not_available",
		Domain: "safedep.io",
		Metadata: map[string]string{
			"feature": "FEATURE_ENDPOINT_SYNC",
		},
	})
	require.NoError(t, err)

	for range anyNesting {
		detail, err = anypb.New(detail)
		require.NoError(t, err)
	}

	st := status.New(codes.PermissionDenied, "service execution failed: entitlement verification failed")
	stProto := st.Proto()
	stProto.Details = append(stProto.Details, detail)

	return status.FromProto(stProto).Err()
}

func TestSyncFailureError(t *testing.T) {
	wrap := func(err error) error {
		return fmt.Errorf("endpointsync: sync failed: %w", err)
	}

	tests := []struct {
		name          string
		err           error
		origin        cloudauth.KeyOrigin
		expectedCode  string
		expectedHuman string
		expectedHelp  string
	}{
		{
			name:          "sync already in progress",
			err:           fmt.Errorf("outer: %w", audit.ErrSyncInProgress),
			expectedCode:  errcodes.Lifecycle,
			expectedHuman: "Another cloud sync is already in progress",
		},
		{
			name:          "missing credentials maps to setup guidance",
			err:           fmt.Errorf("init cloud sync client: failed to resolve cloud credentials: %w", cloud.ErrMissingCredentials),
			expectedCode:  errcodes.CloudCredentialsNotFound,
			expectedHuman: "SafeDep Cloud credentials are not configured",
			expectedHelp:  "Run 'pmg cloud login' to store credentials, or set the SAFEDEP_API_KEY and SAFEDEP_TENANT_ID environment variables",
		},
		{
			name:          "authentication failure gets credential guidance",
			err:           wrap(status.Error(codes.Unauthenticated, "invalid API key")),
			expectedCode:  usefulerror.ErrAuthenticationFailed,
			expectedHuman: "SafeDep Cloud rejected your credentials",
			expectedHelp:  "Run 'pmg cloud login' to update credentials, or check the SAFEDEP_API_KEY and SAFEDEP_TENANT_ID environment variables",
		},
		{
			name:          "a rejected keychain key asks for a new key",
			err:           wrap(status.Error(codes.Unauthenticated, "invalid API key")),
			origin:        cloudauth.KeyOriginKeychain,
			expectedCode:  usefulerror.ErrAuthenticationFailed,
			expectedHuman: "SafeDep Cloud rejected your credentials",
			expectedHelp:  "Run 'pmg cloud login' with a new API key",
		},
		{
			name:          "a rejected environment key names the variables",
			err:           wrap(status.Error(codes.Unauthenticated, "invalid API key")),
			origin:        cloudauth.KeyOriginEnvironment,
			expectedCode:  usefulerror.ErrAuthenticationFailed,
			expectedHuman: "SafeDep Cloud rejected your credentials",
			expectedHelp:  "Set SAFEDEP_API_KEY and SAFEDEP_TENANT_ID to a valid API key and its tenant",
		},
		{
			name:          "a rejected credential file names the file",
			err:           wrap(status.Error(codes.Unauthenticated, "invalid API key")),
			origin:        cloudauth.KeyOriginCredentialFile,
			expectedCode:  usefulerror.ErrAuthenticationFailed,
			expectedHuman: "SafeDep Cloud rejected your credentials",
			expectedHelp:  "Check the credential file that PMG_CLOUD_CREDENTIAL_FILE names",
		},
		{
			name:          "entitlement failure passes through",
			err:           wrap(entitlementStatusErr(t, 0)),
			expectedCode:  usefulerror.ErrMissingEntitlements,
			expectedHuman: "Permission denied",
			expectedHelp:  "Access to this feature requires a SafeDep subscription. See https://safedep.io/pricing",
		},
		{
			name: "entitlement failure with re-wrapped details passes through",
			// Old control-tower serror.Add re-packed details into nested Any
			// layers; classification must survive that wire format too.
			err:           wrap(entitlementStatusErr(t, 2)),
			expectedCode:  usefulerror.ErrMissingEntitlements,
			expectedHuman: "Permission denied",
		},
		{
			name:          "permission denied without entitlement detail gets credential guidance",
			err:           wrap(status.Error(codes.PermissionDenied, "no access")),
			expectedCode:  usefulerror.ErrAuthorizationFailed,
			expectedHuman: "SafeDep Cloud rejected your credentials",
			expectedHelp:  "Run 'pmg cloud login' to update credentials, or check the SAFEDEP_API_KEY and SAFEDEP_TENANT_ID environment variables",
		},
		{
			name:          "server internal error passes through",
			err:           wrap(status.Error(codes.Internal, "server closed the stream without sending trailers")),
			expectedCode:  usefulerror.ErrInternalServerError,
			expectedHuman: "Internal server error",
		},
		{
			name:          "unclassifiable error falls back to network",
			err:           errors.New("something odd happened"),
			expectedCode:  errcodes.Network,
			expectedHuman: "Failed to sync events to SafeDep Cloud",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := syncFailureError(tt.err, tt.origin)
			require.Error(t, err)

			usefulErr, ok := usefulerror.AsUsefulError(err)
			require.True(t, ok)

			assert.Equal(t, tt.expectedCode, usefulErr.Code())
			assert.Equal(t, tt.expectedHuman, usefulErr.HumanError())
			if tt.expectedHelp != "" {
				assert.Equal(t, tt.expectedHelp, usefulErr.Help())
			}
		})
	}
}

func TestPolicyFetchFailureError(t *testing.T) {
	offline := fmt.Errorf("fetch policy: %w", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")})

	tests := []struct {
		name          string
		err           error
		applied       uint64
		expectedCode  string
		expectedHuman string
		expectedHelp  string
	}{
		{
			name:          "offline with an applied policy names its revision",
			err:           offline,
			applied:       52,
			expectedCode:  errcodes.Network,
			expectedHuman: "Cannot fetch the cloud policy from SafeDep Cloud. The last policy still applies (revision 52)",
			expectedHelp:  "Check your network connectivity and ensure SafeDep Cloud is reachable",
		},
		{
			name:          "offline with no applied policy says so",
			err:           offline,
			expectedCode:  errcodes.Network,
			expectedHuman: "Cannot fetch the cloud policy from SafeDep Cloud. No cloud policy applies yet",
		},
		{
			name:          "a timeout keeps its code",
			err:           status.Error(codes.DeadlineExceeded, "deadline exceeded"),
			applied:       52,
			expectedCode:  usefulerror.ErrGatewayTimeout,
			expectedHuman: "Cannot fetch the cloud policy from SafeDep Cloud. The last policy still applies (revision 52)",
		},
		{
			name:          "a server error says which policy applies and keeps its help",
			err:           status.Error(codes.Internal, "server closed the stream without sending trailers"),
			applied:       52,
			expectedCode:  usefulerror.ErrInternalServerError,
			expectedHuman: "Cannot fetch the cloud policy from SafeDep Cloud. The last policy still applies (revision 52)",
			expectedHelp:  "Retry the operation. If the error continues, contact SafeDep support.",
		},
		{
			name:          "a server outage keeps its help",
			err:           status.Error(codes.Unavailable, "service unavailable"),
			applied:       52,
			expectedCode:  usefulerror.ErrServiceUnavailable,
			expectedHuman: "Cannot fetch the cloud policy from SafeDep Cloud. The last policy still applies (revision 52)",
			expectedHelp:  "The service is temporarily unavailable. Retry after a short delay.",
		},
		{
			name:          "a missing entitlement keeps its own text",
			err:           entitlementStatusErr(t, 0),
			applied:       52,
			expectedCode:  usefulerror.ErrMissingEntitlements,
			expectedHuman: "Permission denied",
		},
		{
			name:          "an authentication failure gets credential guidance",
			err:           status.Error(codes.Unauthenticated, "invalid API key"),
			applied:       52,
			expectedCode:  usefulerror.ErrAuthenticationFailed,
			expectedHuman: "SafeDep Cloud rejected your credentials",
			expectedHelp:  "Run 'pmg cloud login' to update credentials, or check the SAFEDEP_API_KEY and SAFEDEP_TENANT_ID environment variables",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usefulErr, ok := usefulerror.AsUsefulError(policyFetchFailureError(tt.err, tt.applied, cloudauth.KeyOriginUnknown))
			require.True(t, ok)

			assert.Equal(t, tt.expectedCode, usefulErr.Code())
			assert.Equal(t, tt.expectedHuman, usefulErr.HumanError())
			if tt.expectedHelp != "" {
				assert.Equal(t, tt.expectedHelp, usefulErr.Help())
			}
		})
	}
}

func TestRequirePolicyError(t *testing.T) {
	offline := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}

	tests := []struct {
		name          string
		err           error
		expectedCode  string
		expectedHuman string
	}{
		{
			name:          "a cloud that pmg cannot reach",
			err:           fmt.Errorf("%w: %w", cloudsync.ErrNoPolicy, offline),
			expectedCode:  errcodes.Network,
			expectedHuman: "Cannot fetch the cloud policy from SafeDep Cloud. No cloud policy applies yet",
		},
		{
			name:          "missing credentials",
			err:           fmt.Errorf("%w: %w", cloudsync.ErrNoPolicy, cloud.ErrMissingCredentials),
			expectedCode:  errcodes.CloudCredentialsNotFound,
			expectedHuman: "SafeDep Cloud credentials are not configured",
		},
		{
			name:          "a busy sync lock",
			err:           fmt.Errorf("%w: %w", cloudsync.ErrNoPolicy, audit.ErrSyncInProgress),
			expectedCode:  errcodes.Lifecycle,
			expectedHuman: "Another cloud sync is already in progress",
		},
		{
			name:          "a policy that pmg rejects",
			err:           fmt.Errorf("%w: %w", cloudsync.ErrNoPolicy, cloudsync.ErrPolicyRejected),
			expectedCode:  errcodes.Lifecycle,
			expectedHuman: "No cloud policy applies. pmg did not accept the policy that it fetched",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usefulErr, ok := usefulerror.AsUsefulError(requirePolicyError(tt.err, cloudauth.KeyOriginUnknown))
			require.True(t, ok)
			assert.Equal(t, tt.expectedCode, usefulErr.Code())
			assert.Equal(t, tt.expectedHuman, usefulErr.HumanError())
		})
	}
}

func TestPolicyWarningText(t *testing.T) {
	assert.Equal(t,
		"Cannot fetch the cloud policy (offline). The last policy still applies (revision 52).",
		policyWarningText(&cloudsync.PolicyWarning{Revision: 52, Err: errors.New("offline")}))
	assert.Equal(t,
		"Your SafeDep plan does not include the cloud policy, so no cloud policy applies. "+
			"Set 'cloud.policy: false' in the PMG config to turn off this warning.",
		policyWarningText(&cloudsync.PolicyWarning{Err: entitlementStatusErr(t, 0)}))
}

func TestStoredKeyCheck(t *testing.T) {
	day := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		status        cloudauth.KeyStatus
		expectedHuman string
		expectedHelp  string
		expectedWarn  string
	}{
		{
			name:          "an expired keychain key stops the sync",
			status:        cloudauth.KeyStatus{Origin: cloudauth.KeyOriginKeychain, State: cloudauth.KeyStateExpired, ExpiresAt: day},
			expectedHuman: "The SafeDep Cloud API key expired on 2026-11-20",
			expectedHelp:  "Run 'pmg cloud login' with a new API key",
		},
		{
			name:         "a key that expires soon warns",
			status:       cloudauth.KeyStatus{Origin: cloudauth.KeyOriginKeychain, State: cloudauth.KeyStateExpiring, ExpiresAt: day},
			expectedWarn: "The SafeDep Cloud API key expires on 2026-11-20. Run 'pmg cloud login' with a new API key before that date.",
		},
		{
			name:   "a valid key passes",
			status: cloudauth.KeyStatus{Origin: cloudauth.KeyOriginKeychain, State: cloudauth.KeyStateValid, ExpiresAt: day},
		},
		{
			name:   "a key with no recorded expiry passes",
			status: cloudauth.KeyStatus{Origin: cloudauth.KeyOriginEnvironment},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning, err := storedKeyCheck(tt.status)
			assert.Equal(t, tt.expectedWarn, warning)

			if tt.expectedHuman == "" {
				assert.NoError(t, err)
				return
			}
			usefulErr, ok := usefulerror.AsUsefulError(err)
			require.True(t, ok)
			assert.Equal(t, usefulerror.ErrAuthenticationFailed, usefulErr.Code())
			assert.Equal(t, tt.expectedHuman, usefulErr.HumanError())
			assert.Equal(t, tt.expectedHelp, usefulErr.Help())
		})
	}
}
