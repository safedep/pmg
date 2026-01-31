package config

import "github.com/spf13/cobra"

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
		globalConfig.Config.Paranoid, "Perform active scanning of unknown packages (slow)")
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

	// Hide the experimental proxy mode flag but keep it for backward compatibility
	cmd.PersistentFlags().MarkHidden("experimental-proxy-mode")
}
