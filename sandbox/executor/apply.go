package executor

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/eventlog"
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
			return nil, usefulerror.Useful().
				WithCode(usefulerror.ErrCodeInvalidArgument).
				WithHumanError(fmt.Sprintf("Failed to load sandbox profile override: %s", cfg.SandboxProfileOverride)).
				WithHelp("Please verify the sandbox profile path and try again.").
				WithAdditionalHelp("See more at: https://github.com/safedep/pmg/blob/main/docs/sandbox.md").
				Wrap(err)
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
				WithCode(usefulerror.ErrCodeNotFound).
				WithHumanError(fmt.Sprintf("No sandbox policy configured for %s", pmName)).
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

	// Apply runtime --sandbox-allow overrides to the policy before execution
	if len(cfg.SandboxAllowOverrides) > 0 {
		applyRuntimeOverrides(policy, cfg.SandboxAllowOverrides)
		logSandboxOverridesToEventLog(policy.Name, cfg.SandboxAllowOverrides)
	}

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
		return nil, usefulerror.Useful().
			WithCode(usefulerror.ErrCodeInvalidArgument).
			WithHumanError(fmt.Sprintf("Sandbox %s is required but not available", sb.Name())).
			WithHelp("Please install the sandbox provider and try again.").
			WithAdditionalHelp("See more at: https://github.com/safedep/pmg/blob/main/docs/sandbox.md").
			Wrap(fmt.Errorf("sandbox %s is required but not available", sb.Name()))
	}

	log.Debugf("Running %s in %s sandbox with policy %s", pmName, sb.Name(), policy.Name)

	result, err := sb.Execute(ctx, cmd, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to setup sandbox: %w", err)
	}

	return result, nil
}

// applyRuntimeOverrides applies --sandbox-allow overrides to the policy.
// Overrides append to allow lists and remove exact matches from corresponding deny lists
// so that deny rules don't shadow the explicit override. Only full-path exact matches are
// removed — glob and wildcard deny patterns are never modified to stay secure by default.
func applyRuntimeOverrides(policy *sandbox.SandboxPolicy, overrides []config.SandboxAllowOverride) {
	for _, override := range overrides {
		switch override.Type {
		case config.SandboxAllowRead:
			log.Infof("Sandbox override: allowing read access to %s", override.Value)
			policy.Filesystem.AllowRead = append(policy.Filesystem.AllowRead, override.Value)
			policy.Filesystem.DenyRead = removeExactMatch(policy.Filesystem.DenyRead, override.Value)

		case config.SandboxAllowWrite:
			log.Infof("Sandbox override: allowing write access to %s", override.Value)
			policy.Filesystem.AllowWrite = append(policy.Filesystem.AllowWrite, override.Value)
			policy.Filesystem.DenyWrite = removeExactMatch(policy.Filesystem.DenyWrite, override.Value)

		case config.SandboxAllowExec:
			log.Infof("Sandbox override: allowing execution of %s", override.Value)
			policy.Process.AllowExec = append(policy.Process.AllowExec, override.Value)
			policy.Process.DenyExec = removeExactMatch(policy.Process.DenyExec, override.Value)

		case config.SandboxAllowNetConnect:
			log.Infof("Sandbox override: allowing outbound connection to %s", override.Value)
			policy.Network.AllowOutbound = append(policy.Network.AllowOutbound, override.Value)

		case config.SandboxAllowNetBind:
			log.Infof("Sandbox override: allowing network bind on %s", override.Value)
			policy.Network.AllowBind = append(policy.Network.AllowBind, override.Value)

			// Enable AllowNetworkBind so the translator emits bind rules.
			// Without this, AllowBind entries would be ignored on some platforms.
			policy.AllowNetworkBind = utils.PtrTo(true)
		}
	}
}

// removeExactMatch removes entries from the slice that exactly match the given value.
// Glob patterns and wildcards in the slice are never matched. Only literal string
// equality is used. This keeps broad deny rules intact while allowing targeted overrides.
func removeExactMatch(slice []string, value string) []string {
	result := make([]string, 0, len(slice))
	for _, entry := range slice {
		if entry == value {
			log.Infof("Sandbox override: removing conflicting deny rule for %s", value)
			continue
		}

		result = append(result, entry)
	}

	return result
}

// logSandboxOverridesToEventLog records sandbox allow overrides in the audit event log.
func logSandboxOverridesToEventLog(profileName string, overrides []config.SandboxAllowOverride) {
	entries := make([]map[string]string, 0, len(overrides))
	for _, o := range overrides {
		entries = append(entries, map[string]string{
			"type":  string(o.Type),
			"value": o.Value,
		})
	}

	eventlog.LogSandboxOverrides(profileName, entries)
}
