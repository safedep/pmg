package config

import (
	"fmt"

	"github.com/spf13/cobra"
)

// sandboxAllowRaw holds the raw --sandbox-allow flag values before parsing.
var sandboxAllowRaw []string

// ApplyCobraFlags applies the cobra flags to the command.
// These flags are local concern of the config package. This helper function is used
// to bind them to the Cobra. The default values are taken from the global configuration,
// allowing for overriding the configuration at runtime.
func ApplyCobraFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&globalConfig.Config.Transitive, "transitive",
		globalConfig.Config.Transitive, "Resolve transitive dependencies")
	cmd.PersistentFlags().IntVar(&globalConfig.Config.TransitiveDepth, "transitive-depth",
		globalConfig.Config.TransitiveDepth, "Maximum depth of transitive dependencies to resolve")
	cmd.PersistentFlags().BoolVar(&globalConfig.Config.IncludeDevDependencies, "include-dev-dependencies",
		globalConfig.Config.IncludeDevDependencies, "Include dev dependencies in the dependency graph (slows down resolution)")
	cmd.PersistentFlags().BoolVar(&globalConfig.DryRun, "dry-run",
		globalConfig.DryRun, "Dry run skips execution of package manager")
	cmd.PersistentFlags().BoolVar(&globalConfig.Config.Paranoid, "paranoid",
		globalConfig.Config.Paranoid, "Enable high-security defaults (treat suspicious as malicious)")
	cmd.PersistentFlags().BoolVar(&globalConfig.Config.SkipEventLogging, "skip-event-log",
		globalConfig.Config.SkipEventLogging, "Skip event logging")
	cmd.PersistentFlags().BoolVar(&globalConfig.Config.ExperimentalProxyMode, "experimental-proxy-mode",
		globalConfig.Config.ExperimentalProxyMode, "Use experimental proxy-based interception (EXPERIMENTAL)")
	cmd.PersistentFlags().BoolVar(&globalConfig.Config.ProxyMode, "proxy-mode",
		globalConfig.Config.ProxyMode, "Use proxy based interception")
	cmd.PersistentFlags().BoolVar(&globalConfig.Config.Sandbox.Enabled, "sandbox",
		globalConfig.Config.Sandbox.Enabled, "Enable sandbox mode to isolate package manager processes (EXPERIMENTAL)")
	cmd.PersistentFlags().BoolVar(&globalConfig.Config.Sandbox.EnforceAlways, "sandbox-enforce",
		globalConfig.Config.Sandbox.EnforceAlways, "Apply sandbox to all commands, not just install commands (requires --sandbox)")
	cmd.PersistentFlags().StringVar(&globalConfig.SandboxProfileOverride, "sandbox-profile",
		globalConfig.SandboxProfileOverride, "Override sandbox policy profile (built-in name or path to custom YAML)")
	cmd.PersistentFlags().StringArrayVar(&sandboxAllowRaw, "sandbox-allow",
		nil, "Add runtime sandbox allow rule (type=value). Types: read, write, exec, net-connect, net-bind")

	// Hide the experimental proxy mode flag but keep it for backward compatibility
	_ = cmd.PersistentFlags().MarkHidden("experimental-proxy-mode")
}

// FinalizeSandboxAllowOverrides parses the raw --sandbox-allow flag values
// and stores the validated overrides in the global config. This must be called
// after cobra flag parsing is complete (e.g., in PersistentPreRun).
func FinalizeSandboxAllowOverrides() error {
	if len(sandboxAllowRaw) == 0 {
		return nil
	}

	overrides, err := parseSandboxAllowOverrides(sandboxAllowRaw)
	if err != nil {
		return fmt.Errorf("failed to parse --sandbox-allow flags: %w", err)
	}

	globalConfig.SandboxAllowOverrides = overrides
	return nil
}
