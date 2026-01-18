package flows

import (
	"context"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/packagemanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSandboxPolicyHook(t *testing.T) {
	tests := []struct {
		name                 string
		sandboxEnabled       bool
		enforceAlways        bool
		isInstallationCmd    bool
		expectedSandboxState bool
		description          string
	}{
		{
			name:                 "sandbox disabled - should remain disabled regardless of other settings",
			sandboxEnabled:       false,
			enforceAlways:        true,
			isInstallationCmd:    true,
			expectedSandboxState: false,
			description:          "When sandbox is disabled, it should stay disabled",
		},
		{
			name:                 "sandbox enabled with enforce always true - should enable for any command",
			sandboxEnabled:       true,
			enforceAlways:        true,
			isInstallationCmd:    false,
			expectedSandboxState: true,
			description:          "When EnforceAlways is true, sandbox should be enabled for any command",
		},
		{
			name:                 "sandbox enabled with enforce always true and installation command",
			sandboxEnabled:       true,
			enforceAlways:        true,
			isInstallationCmd:    true,
			expectedSandboxState: true,
			description:          "When EnforceAlways is true, sandbox should be enabled for installation commands",
		},
		{
			name:                 "sandbox enabled with enforce always false and installation command",
			sandboxEnabled:       true,
			enforceAlways:        false,
			isInstallationCmd:    true,
			expectedSandboxState: true,
			description:          "When EnforceAlways is false but command is installation, sandbox should be enabled",
		},
		{
			name:                 "sandbox enabled with enforce always false and non-installation command",
			sandboxEnabled:       true,
			enforceAlways:        false,
			isInstallationCmd:    false,
			expectedSandboxState: false,
			description:          "When EnforceAlways is false and command is not installation, sandbox should be disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test config
			setupTestConfig(t, tt.sandboxEnabled, tt.enforceAlways)

			// Create mock parsed command
			parsedCommand := createMockParsedCommand(tt.isInstallationCmd)

			// Create the hook
			hook := NewSandboxPolicyHook()
			require.NotNil(t, hook, "NewSandboxPolicyHook should return a non-nil hook")

			// Execute the hook
			ctx := context.Background()
			resultCtx, err := hook.BeforeFlow(ctx, parsedCommand)

			// Assert no error
			assert.NoError(t, err, "Hook execution should not return an error")
			assert.Equal(t, ctx, resultCtx, "Context should be returned unchanged")

			// Assert sandbox state
			currentConfig := config.Get()
			assert.Equal(t, tt.expectedSandboxState, currentConfig.Config.Sandbox.Enabled,
				tt.description)
		})
	}
}

func TestHookWithNilParsedCommand(t *testing.T) {
	setupTestConfig(t, true, false)

	hook := NewSandboxPolicyHook()
	ctx := context.Background()

	_, err := hook.BeforeFlow(ctx, nil)
	assert.Error(t, err)
}

// Helper functions
func setupTestConfig(t *testing.T, sandboxEnabled, enforceAlways bool) {
	// Get the current config and modify it directly
	// Since config is global, we modify it in place for testing
	cfg := config.Get()
	cfg.Config.Sandbox.Enabled = sandboxEnabled
	cfg.Config.Sandbox.EnforceAlways = enforceAlways
}

func createMockParsedCommand(isInstallationCommand bool) *packagemanager.ParsedCommand {
	pc := &packagemanager.ParsedCommand{}

	if isInstallationCommand {
		pc.IsManifestInstall = true
	}

	return pc
}
