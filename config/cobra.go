package config

import "github.com/spf13/cobra"

// ApplyCobraFlags applies the cobra flags to the command.
// These flags are local concern of the config package. This helper function is used
// to bind them to the Cobra command.
func ApplyCobraFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&globalConfig.Config.Transitive, "transitive", true, "Resolve transitive dependencies")
	cmd.PersistentFlags().IntVar(&globalConfig.Config.TransitiveDepth, "transitive-depth", 5,
		"Maximum depth of transitive dependencies to resolve")
	cmd.PersistentFlags().BoolVar(&globalConfig.Config.IncludeDevDependencies, "include-dev-dependencies", false,
		"Include dev dependencies in the dependency graph (slows down resolution)")
	cmd.PersistentFlags().BoolVar(&globalConfig.DryRun, "dry-run", false, "Dry run skips execution of package manager")
	cmd.PersistentFlags().BoolVar(&globalConfig.Config.Paranoid, "paranoid", false, "Perform active scanning of unknown packages (slow)")
}
