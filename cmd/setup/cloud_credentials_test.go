package setup

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudauth"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestCredentialsLabel(t *testing.T) {
	day := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	keychain := func(state cloudauth.KeyState) cloudauth.KeyStatus {
		return cloudauth.KeyStatus{Origin: cloudauth.KeyOriginKeychain, State: state, ExpiresAt: day}
	}

	tests := []struct {
		name       string
		status     cloudauth.KeyStatus
		resolveErr error
		want       string
	}{
		{name: "expired keychain key", status: keychain(cloudauth.KeyStateExpired), want: "keychain (API key expired on 2026-11-20 09:00 UTC)"},
		{name: "keychain key that expires soon", status: keychain(cloudauth.KeyStateExpiring), want: "keychain (API key expires on 2026-11-20 09:00 UTC)"},
		{name: "valid keychain key", status: keychain(cloudauth.KeyStateValid), want: "keychain (API key expires on 2026-11-20 09:00 UTC)"},
		{name: "keychain key with no recorded expiry", status: keychain(cloudauth.KeyStateUnknown), want: "keychain"},
		{name: "environment", status: cloudauth.KeyStatus{Origin: cloudauth.KeyOriginEnvironment}, want: "environment (SAFEDEP_API_KEY, SAFEDEP_TENANT_ID)"},
		{name: "credential file", status: cloudauth.KeyStatus{Origin: cloudauth.KeyOriginCredentialFile}, want: "credential file (PMG_CLOUD_CREDENTIAL_FILE)"},
		{
			name:       "credential file that pmg cannot use",
			status:     cloudauth.KeyStatus{Origin: cloudauth.KeyOriginCredentialFile},
			resolveErr: errors.New("open the credential file"),
			want:       "credential file (PMG_CLOUD_CREDENTIAL_FILE), not usable. Run 'pmg setup doctor' for the error",
		},
		{
			name:       "no credentials",
			resolveErr: cloud.ErrMissingCredentials,
			want:       "not configured (run 'pmg cloud login' or set SAFEDEP_API_KEY and SAFEDEP_TENANT_ID)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, credentialsLabel(tt.status, tt.resolveErr))
		})
	}
}

func TestCloudCredentialsCheckRunsOnlyWithCloudOn(t *testing.T) {
	// The credential file makes the result the same on every host. pmg then
	// reads no keychain and no environment key.
	t.Setenv(cloudauth.CredentialFileEnv, filepath.Join(t.TempDir(), "missing.json"))
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	config.Reload()
	t.Cleanup(config.Reload)

	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("cloud.enabled=%v", enabled), func(t *testing.T) {
			cfg := config.Get()
			cfg.Config.Cloud.Enabled = enabled

			results := runCoreChecks(cfg)
			idx := slices.IndexFunc(results, func(r doctor.CheckResult) bool { return r.Name == checkCloudCredentials })

			if !enabled {
				assert.Equal(t, -1, idx)
				return
			}
			require.NotEqual(t, -1, idx)
			result := results[idx]
			assert.Equal(t, doctor.StatusFail, result.Status)
			assert.Contains(t, result.Message, "pmg cannot use the credential file that PMG_CLOUD_CREDENTIAL_FILE names (open the credential file")
		})
	}
}
