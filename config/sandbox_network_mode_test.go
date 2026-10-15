package config

import (
	"os"
	"path/filepath"
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

func TestSandboxNetworkModeLoader(t *testing.T) {
	originalConfig := globalConfig
	t.Cleanup(func() {
		globalConfig = originalConfig
		configLoadErr = nil
	})

	tests := []struct {
		name        string
		contents    string
		env         string
		wantMode    string
		wantLoadErr bool
	}{
		{name: "absent key defaults to audit", contents: "sandbox:\n  enabled: true\n", wantMode: SandboxNetworkModeAudit},
		{name: "enforce from the file", contents: "sandbox:\n  network_mode: enforce\n", wantMode: SandboxNetworkModeEnforce},
		{name: "enforce from the environment", contents: "sandbox:\n  network_mode: audit\n", env: "enforce", wantMode: SandboxNetworkModeEnforce},
		{name: "invalid value fails the load closed", contents: "sandbox:\n  enabled: true\n  network_mode: bogus\n", wantMode: SandboxNetworkModeAudit, wantLoadErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configDir := t.TempDir()
			t.Setenv(pmgConfigDirEnvKey, configDir)
			t.Setenv("PMG_SANDBOX_NETWORK_MODE", tt.env)
			require.NoError(t, os.WriteFile(filepath.Join(configDir, pmgConfigFileName), []byte(tt.contents), 0o644))

			initConfig()

			assert.Equal(t, tt.wantMode, Get().Config.Sandbox.NetworkMode)
			if !tt.wantLoadErr {
				assert.NoError(t, LoadError())
				return
			}

			require.Error(t, LoadError())
			var modeErr *SandboxNetworkModeError
			assert.ErrorAs(t, LoadError(), &modeErr)
			assert.False(t, Get().Config.Sandbox.Enabled, "a failed load keeps the defaults")
		})
	}
}
