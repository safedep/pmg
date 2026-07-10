package cloud

import (
	"errors"
	"fmt"
	"testing"

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
	}{
		{
			name:          "sync already in progress",
			err:           fmt.Errorf("outer: %w", audit.ErrSyncInProgress),
			expectedCode:  errcodes.Lifecycle,
			expectedHuman: "Another cloud sync is already in progress",
		},
		{
			name:          "authentication failure passes through",
			err:           wrap(status.Error(codes.Unauthenticated, "invalid API key")),
			expectedCode:  usefulerror.ErrAuthenticationFailed,
			expectedHuman: "Authentication failed",
		},
		{
			name:          "entitlement failure passes through",
			err:           wrap(entitlementStatusErr(t, 0)),
			expectedCode:  usefulerror.ErrMissingEntitlements,
			expectedHuman: "Permission denied",
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
			name:          "permission denied without entitlement detail",
			err:           wrap(status.Error(codes.PermissionDenied, "no access")),
			expectedCode:  usefulerror.ErrAuthorizationFailed,
			expectedHuman: "Permission denied",
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
		})
	}
}
