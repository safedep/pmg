package setup

import (
	"errors"
	"testing"
	"time"

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
			resolveErr:  errors.New("failed to resolve cloud credentials"),
			wantStatus:  doctor.StatusWarn,
			wantMessage: "Cloud sync is on, but pmg finds no SafeDep Cloud credentials",
			wantFix:     "Run: pmg cloud login",
		},
		{
			name:        "expired key",
			status:      keychain(cloudauth.KeyStateExpired),
			wantStatus:  doctor.StatusFail,
			wantMessage: "The API key from the keychain expired on 2026-11-20",
			wantFix:     "Run 'pmg cloud login' with a new API key",
		},
		{
			name:        "key that expires soon",
			status:      keychain(cloudauth.KeyStateExpiring),
			wantStatus:  doctor.StatusWarn,
			wantMessage: "The API key from the keychain expires on 2026-11-20",
			wantFix:     "Run 'pmg cloud login' with a new API key",
		},
		{
			name:        "valid key",
			status:      keychain(cloudauth.KeyStateValid),
			wantStatus:  doctor.StatusPass,
			wantMessage: "API key from the keychain, expires on 2026-11-20",
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
		{cloudauth.KeyStateExpired, "keychain (API key expired on 2026-11-20)"},
		{cloudauth.KeyStateExpiring, "keychain (API key expires on 2026-11-20)"},
		{cloudauth.KeyStateValid, "keychain (API key expires on 2026-11-20)"},
		{cloudauth.KeyStateUnknown, "keychain"},
	}

	for _, tt := range tests {
		got := keychainCredentialsLabel(cloudauth.KeyStatus{Origin: cloudauth.KeyOriginKeychain, State: tt.state, ExpiresAt: day})
		assert.Equal(t, tt.want, got)
	}
}
