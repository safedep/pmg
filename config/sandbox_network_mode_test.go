package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateSandboxNetworkMode(t *testing.T) {
	tests := []struct {
		mode    string
		wantErr bool
	}{
		{mode: "", wantErr: false},
		{mode: SandboxNetworkModeAudit, wantErr: false},
		{mode: SandboxNetworkModeEnforce, wantErr: false},
		{mode: "Audit", wantErr: true},
		{mode: "observe", wantErr: true},
		{mode: "true", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			err := ValidateSandboxNetworkMode(tc.mode)
			if !tc.wantErr {
				assert.NoError(t, err)
				return
			}

			var modeErr *SandboxNetworkModeError
			require.ErrorAs(t, err, &modeErr)
			assert.Equal(t, tc.mode, modeErr.Mode)
			assert.Contains(t, err.Error(), "expected audit or enforce")
		})
	}
}

func TestDefaultConfigSandboxNetworkModeIsAudit(t *testing.T) {
	assert.Equal(t, SandboxNetworkModeAudit, DefaultConfig().Config.Sandbox.NetworkMode)
}

func TestSandboxPolicyTemplatePaths(t *testing.T) {
	cfg := RuntimeConfig{configDir: "/etc/pmg"}
	cfg.Config.Sandbox.PolicyTemplates = map[string]SandboxPolicyTemplate{
		"relative": {Path: "profiles/ci.yml"},
		"absolute": {Path: "/srv/profiles/runner.yml"},
	}

	paths := cfg.SandboxPolicyTemplatePaths()
	assert.Equal(t, "/etc/pmg/profiles/ci.yml", paths["relative"])
	assert.Equal(t, "/srv/profiles/runner.yml", paths["absolute"])
}
