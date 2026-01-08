package sandbox

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
)

// ApplySandbox applies sandbox isolation to the command if sandbox mode is enabled.
// This is a helper function used by both guard and proxy flows to avoid code duplication.
//
// Parameters:
//   - ctx: Context for the sandbox execution
//   - cmd: The exec.Cmd to be sandboxed (will be modified in place)
//   - pmName: Package manager name (e.g., "npm", "pip") used to determine the sandbox policy to apply
//   - mode: Optional mode description for logging (e.g., "proxy mode", empty for default)
//
// Returns an error if sandbox setup fails, or nil if sandbox is not enabled/available.
// Gracefully degrades with warnings if sandbox is unavailable on the platform.
func ApplySandbox(ctx context.Context, cmd *exec.Cmd, pmName string, mode string) error {
	cfg := config.Get()

	// Check if sandbox is enabled globally
	if !cfg.Config.Sandbox.Enabled {
		return nil // Sandbox disabled, skip
	}

	// Check if sandbox policy exists for this package manager
	policyRef, exists := cfg.Config.Sandbox.Policies[pmName]
	if !exists || !policyRef.Enabled {
		log.Debugf("No sandbox policy enabled for %s", pmName)
		return nil
	}

	// Load the sandbox policy
	registry := NewProfileRegistry()
	policy, err := registry.GetProfile(policyRef.Profile)
	if err != nil {
		return fmt.Errorf("failed to load sandbox policy %s: %w", policyRef.Profile, err)
	}

	// Validate that the policy applies to this package manager
	if !policy.AppliesToPackageManager(pmName) {
		log.Warnf("Sandbox policy %s does not apply to %s", policy.Name, pmName)
		return nil
	}

	// Create platform-specific sandbox
	sb, err := NewSandbox()
	if err != nil {
		// Sandbox not available on this platform - log warning and continue
		log.Warnf("Sandbox not available on this platform: %v", err)
		log.Warnf("Continuing without sandbox protection")
		return nil
	}

	if !sb.IsAvailable() {
		log.Warnf("Sandbox %s not available, running without sandbox", sb.Name())
		return nil
	}

	// Build log message with optional mode suffix
	logMsg := fmt.Sprintf("Running %s in %s sandbox with policy %s", pmName, sb.Name(), policy.Name)
	if mode != "" {
		logMsg += fmt.Sprintf(" (%s)", mode)
	}
	log.Infof(logMsg)

	// Execute sandbox setup (modifies cmd in place)
	// Note: The sandbox preserves any environment variables already set on cmd.Env
	if err := sb.Execute(ctx, cmd, policy); err != nil {
		return fmt.Errorf("failed to setup sandbox: %w", err)
	}

	return nil
}
