package executor

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/platform"
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
// Returns:
//   - ExecutionResult: Contains execution state. Callers must check result.ShouldRun() before calling cmd.Run().
//   - error: Non-nil if sandbox setup fails
//
// If sandbox is not enabled/available, returns a result indicating the caller should run the command.
// Gracefully degrades with warnings if sandbox is unavailable on the platform.
func ApplySandbox(ctx context.Context, cmd *exec.Cmd, pmName string) (*sandbox.ExecutionResult, error) {
	cfg := config.Get()

	if !cfg.Config.Sandbox.Enabled {
		return sandbox.NewExecutionResult(false), nil
	}

	registry := sandbox.NewProfileRegistry()
	var policy *sandbox.SandboxPolicy
	var err error

	// Check for runtime profile override first (--sandbox-profile flag)
	if cfg.SandboxProfileOverride != "" {
		log.Debugf("Using sandbox profile override: %s", cfg.SandboxProfileOverride)
		policy, err = registry.GetProfile(cfg.SandboxProfileOverride)
		if err != nil {
			return nil, fmt.Errorf("failed to load override sandbox policy %s: %w", cfg.SandboxProfileOverride, err)
		}
	} else {
		// Use configured per-package-manager policy
		policyRef, exists := cfg.Config.Sandbox.Policies[pmName]
		if !exists || !policyRef.Enabled {
			log.Debugf("No sandbox policy enabled for %s", pmName)
			return sandbox.NewExecutionResult(false), nil
		}

		policy, err = registry.GetProfile(policyRef.Profile)
		if err != nil {
			return nil, fmt.Errorf("failed to load sandbox policy %s: %w", policyRef.Profile, err)
		}
	}

	// Validate that the loaded policy applies to this package manager
	if !policy.AppliesToPackageManager(pmName) {
		log.Warnf("Sandbox policy %s does not apply to %s", policy.Name, pmName)
		return sandbox.NewExecutionResult(false), nil
	}

	// Create platform-specific sandbox
	sb, err := platform.NewSandbox()
	if err != nil {
		log.Warnf("Sandbox not available on this platform: %v", err)
		log.Warnf("Continuing without sandbox protection")
		return sandbox.NewExecutionResult(false), nil
	}

	if !sb.IsAvailable() {
		log.Warnf("Sandbox %s not available, running without sandbox", sb.Name())
		return sandbox.NewExecutionResult(false), nil
	}

	log.Debugf("Running %s in %s sandbox with policy %s", pmName, sb.Name(), policy.Name)

	result, err := sb.Execute(ctx, cmd, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to setup sandbox: %w", err)
	}

	// Return result with sandbox reference so caller can defer result.Close()
	return sandbox.NewExecutionResultWithSandbox(result.WasExecuted(), sb), nil
}
