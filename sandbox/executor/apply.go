package executor

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/safedep/pmg/usefulerror"
)

type applySandboxConfig struct {
	sb sandbox.Sandbox
}

type applySandboxOpt func(*applySandboxConfig)

// WithSandbox sets the sandbox to use for the command.
// When not set, the sandbox will be determined by the platform.
func WithSandbox(sb sandbox.Sandbox) applySandboxOpt {
	return func(c *applySandboxConfig) {
		c.sb = sb
	}
}

// ApplySandbox applies sandbox isolation to the command if sandbox mode is enabled.
// This is a helper function used by both guard and proxy flows to avoid code duplication.
//
// This is a security sensitive operation. If sandbox is enabled via. config but not available on the platform,
// it will return an error to avoid running the command without sandbox protection.
func ApplySandbox(ctx context.Context, cmd *exec.Cmd, pmName string, opts ...applySandboxOpt) (*sandbox.ExecutionResult, error) {
	cfg := config.Get()

	if !cfg.Config.Sandbox.Enabled {
		return sandbox.NewExecutionResult(), nil
	}

	applyConfig := &applySandboxConfig{}
	for _, opt := range opts {
		opt(applyConfig)
	}

	registry, err := sandbox.NewProfileRegistry()
	if err != nil {
		return nil, fmt.Errorf("failed to create profile registry: %w", err)
	}

	var policy *sandbox.SandboxPolicy

	if cfg.SandboxProfileOverride != "" {
		log.Debugf("Using sandbox profile override: %s", cfg.SandboxProfileOverride)

		policy, err = registry.GetProfile(cfg.SandboxProfileOverride)
		if err != nil {
			return nil, fmt.Errorf("failed to load override sandbox policy %s: %w", cfg.SandboxProfileOverride, err)
		}
	} else {
		log.Debugf("Looking up sandbox policy for %s", pmName)

		// When a policy is not configured for a package manager, we error out
		// This is to avoid running the command without sandbox protection.
		// To bypass sandbox for a specific package manager, users should explicitly
		// disable for the package manager in the config.
		policyRef, exists := cfg.Config.Sandbox.Policies[pmName]
		if !exists {
			return nil, usefulerror.Useful().
				WithHumanError(fmt.Sprintf("no sandbox policy configured for %s", pmName)).
				WithHelp("Please configure a sandbox policy for this package manager in the config file.").
				WithAdditionalHelp("See https://github.com/safedep/pmg/blob/main/docs/sandbox.md for more information.").
				Wrap(fmt.Errorf("no sandbox policy configured for %s", pmName))
		}

		// The policy is explicitly disabled for this package manager, so we skip sandbox
		if !policyRef.Enabled {
			log.Warnf("sandbox policy %s is explicitly disabled for %s, skipping sandbox", policyRef.Profile, pmName)
			return sandbox.NewExecutionResult(), nil
		}

		log.Debugf("Loading sandbox policy %s", policyRef.Profile)

		// Check if there is a template for the policy and use it if it exists
		// This is a way to override a built-in profile or create a custom profile.
		if template, exists := cfg.Config.Sandbox.PolicyTemplates[policyRef.Profile]; exists {
			if filepath.IsAbs(template.Path) {
				policy, err = registry.GetProfile(template.Path)
				if err != nil {
					return nil, fmt.Errorf("failed to load sandbox policy %s: %w", template.Path, err)
				}
			} else {
				policyPath := filepath.Join(cfg.ConfigDir(), template.Path)
				policy, err = registry.GetProfile(policyPath)
				if err != nil {
					return nil, fmt.Errorf("failed to load sandbox policy %s: %w", policyPath, err)
				}
			}
		} else {
			// Load the policy from the registry by name
			policy, err = registry.GetProfile(policyRef.Profile)
			if err != nil {
				return nil, fmt.Errorf("failed to load sandbox policy %s: %w", policyRef.Profile, err)
			}
		}
	}

	log.Debugf("Loaded sandbox policy %s", policy.Name)

	if !policy.AppliesToPackageManager(pmName) {
		return nil, fmt.Errorf("sandbox policy %s does not apply to %s", policy.Name, pmName)
	}

	var sb sandbox.Sandbox
	if applyConfig.sb != nil {
		sb = applyConfig.sb
	} else {
		sb, err = platform.NewSandbox()
		if err != nil {
			return nil, fmt.Errorf("sandbox not available on this platform: %v", err)
		}
	}

	if !sb.IsAvailable() {
		return nil, fmt.Errorf("sandbox %s is required but not available", sb.Name())
	}

	log.Debugf("Running %s in %s sandbox with policy %s", pmName, sb.Name(), policy.Name)

	result, err := sb.Execute(ctx, cmd, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to setup sandbox: %w", err)
	}

	return result, nil
}
