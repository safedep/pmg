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
func ApplySandbox(ctx context.Context, cmd *exec.Cmd, pmName string, mode string) (*sandbox.ExecutionResult, error) {
	cfg := config.Get()

	if !cfg.Config.Sandbox.Enabled {
		return sandbox.NewExecutionResult(false), nil
	}

	// Lookup the sandbox policy for the package manager based on config
	policyRef, exists := cfg.Config.Sandbox.Policies[pmName]
	if !exists || !policyRef.Enabled {
		log.Debugf("No sandbox policy enabled for %s", pmName)
		return sandbox.NewExecutionResult(false), nil
	}

	registry := sandbox.NewProfileRegistry()
	policy, err := registry.GetProfile(policyRef.Profile)
	if err != nil {
		return nil, fmt.Errorf("failed to load sandbox policy %s: %w", policyRef.Profile, err)
	}

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

	logMsg := fmt.Sprintf("Running %s in %s sandbox with policy %s", pmName, sb.Name(), policy.Name)
	if mode != "" {
		logMsg += fmt.Sprintf(" (%s)", mode)
	}

	log.Infof("%s", logMsg)

	result, err := sb.Execute(ctx, cmd, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to setup sandbox: %w", err)
	}

	return result, nil
}
