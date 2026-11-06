package cloud

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/audit"
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
			err := syncFailureError(tt.err)
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
			usefulErr, ok := usefulerror.AsUsefulError(policyFetchFailureError(tt.err, tt.applied))
			require.True(t, ok)

			assert.Equal(t, tt.expectedCode, usefulErr.Code())
			assert.Equal(t, tt.expectedHuman, usefulErr.HumanError())
			if tt.expectedHelp != "" {
				assert.Equal(t, tt.expectedHelp, usefulErr.Help())
			}
		})
	}
}
