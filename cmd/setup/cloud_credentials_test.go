package setup

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/pmg/internal/cloudauth"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/stretchr/testify/assert"
)

func TestCloudCredentialsResult(t *testing.T) {
	day := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	keychain := func(state cloudauth.KeyState) cloudauth.KeyStatus {
		return cloudauth.KeyStatus{Origin: cloudauth.KeyOriginKeychain, State: state, ExpiresAt: day}
	}

	tests := []struct {
		name        string
		status      cloudauth.KeyStatus
		resolveErr  error
		wantStatus  doctor.CheckStatus
		wantMessage string
		wantFix     string
	}{
		{
			name:        "no credentials",
			resolveErr:  fmt.Errorf("failed to resolve cloud credentials: %w", cloud.ErrMissingCredentials),
			wantStatus:  doctor.StatusWarn,
			wantMessage: "Cloud sync is on, but pmg finds no SafeDep Cloud credentials",
			wantFix:     "Run 'pmg cloud login', or set SAFEDEP_API_KEY and SAFEDEP_TENANT_ID",
		},
		{
			name:        "a credential file that pmg cannot use",
			status:      cloudauth.KeyStatus{Origin: cloudauth.KeyOriginCredentialFile},
			resolveErr:  errors.New("open /run/pmg/credential.json: no such file or directory"),
			wantStatus:  doctor.StatusFail,
			wantMessage: "pmg cannot use the credential file that PMG_CLOUD_CREDENTIAL_FILE names (open /run/pmg/credential.json: no such file or directory)",
			wantFix:     "Run the job again to get a new credential in the file that PMG_CLOUD_CREDENTIAL_FILE names",
		},
		{
			name:        "a keychain that pmg cannot read",
			resolveErr:  errors.New("no credential resolvers available"),
			wantStatus:  doctor.StatusWarn,
			wantMessage: "pmg cannot read the SafeDep Cloud credentials (no credential resolvers available)",
			wantFix:     "Run 'pmg cloud login' to update credentials, or check the SAFEDEP_API_KEY and SAFEDEP_TENANT_ID environment variables",
		},
		{
			name:        "expired key",
			status:      keychain(cloudauth.KeyStateExpired),
			wantStatus:  doctor.StatusFail,
			wantMessage: "The API key from the keychain expired on 2026-11-20 09:00 UTC",
			wantFix:     "Run 'pmg cloud login' with a new API key",
		},
		{
			name:        "key that expires soon",
			status:      keychain(cloudauth.KeyStateExpiring),
			wantStatus:  doctor.StatusWarn,
			wantMessage: "The API key from the keychain expires on 2026-11-20 09:00 UTC",
			wantFix:     "Run 'pmg cloud login' with a new API key",
		},
		{
			name:        "valid key",
			status:      keychain(cloudauth.KeyStateValid),
			wantStatus:  doctor.StatusPass,
			wantMessage: "API key from the keychain, expires on 2026-11-20 09:00 UTC",
		},
		{
			name:        "key with no recorded expiry",
			status:      cloudauth.KeyStatus{Origin: cloudauth.KeyOriginEnvironment},
			wantStatus:  doctor.StatusPass,
			wantMessage: "Credentials from the environment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cloudCredentialsResult(tt.status, tt.resolveErr)
			assert.Equal(t, tt.wantStatus, got.Status)
			assert.Equal(t, tt.wantMessage, got.Message)
			assert.Equal(t, tt.wantFix, got.Fix)
		})
	}
}

func TestKeychainCredentialsLabel(t *testing.T) {
	day := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)

	tests := []struct {
		state cloudauth.KeyState
		want  string
	}{
		{cloudauth.KeyStateExpired, "keychain (API key expired on 2026-11-20 09:00 UTC)"},
		{cloudauth.KeyStateExpiring, "keychain (API key expires on 2026-11-20 09:00 UTC)"},
		{cloudauth.KeyStateValid, "keychain (API key expires on 2026-11-20 09:00 UTC)"},
		{cloudauth.KeyStateUnknown, "keychain"},
	}

	for _, tt := range tests {
		got := keychainCredentialsLabel(cloudauth.KeyStatus{Origin: cloudauth.KeyOriginKeychain, State: tt.state, ExpiresAt: day})
		assert.Equal(t, tt.want, got)
	}
}
