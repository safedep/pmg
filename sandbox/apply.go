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

	if !cfg.Config.Sandbox.Enabled {
		return nil
	}

	// Lookup the sandbox policy for the package manager based on config
	policyRef, exists := cfg.Config.Sandbox.Policies[pmName]
	if !exists || !policyRef.Enabled {
		log.Debugf("No sandbox policy enabled for %s", pmName)
		return nil
	}

	registry := NewProfileRegistry()
	policy, err := registry.GetProfile(policyRef.Profile)
	if err != nil {
		return fmt.Errorf("failed to load sandbox policy %s: %w", policyRef.Profile, err)
	}

	if !policy.AppliesToPackageManager(pmName) {
		log.Warnf("Sandbox policy %s does not apply to %s", policy.Name, pmName)
		return nil
	}

	// Create platform-specific sandbox
	sb, err := NewSandbox()
	if err != nil {
		log.Warnf("Sandbox not available on this platform: %v", err)
		log.Warnf("Continuing without sandbox protection")
		return nil
	}

	if !sb.IsAvailable() {
		log.Warnf("Sandbox %s not available, running without sandbox", sb.Name())
		return nil
	}

	logMsg := fmt.Sprintf("Running %s in %s sandbox with policy %s", pmName, sb.Name(), policy.Name)
	if mode != "" {
		logMsg += fmt.Sprintf(" (%s)", mode)
	}

	log.Infof("%s", logMsg)

	if err := sb.Execute(ctx, cmd, policy); err != nil {
		return fmt.Errorf("failed to setup sandbox: %w", err)
	}

	return nil
}
