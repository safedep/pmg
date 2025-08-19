package npm

import (
	"context"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewNpmCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "npm [action] [package]",
		Short:              "Guard npm package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeNpmFlow(cmd.Context(), args)
			if err != nil {
				ui.ErrorExit(err)
			}

			return nil
		},
	}
}

func executeNpmFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandNpm()
	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultNpmPackageManagerConfig())
	if err != nil {
		ui.Fatalf("Failed to create npm package manager proxy: %s", err)
	}

	config, err := config.FromContext(ctx)
	if err != nil {
		ui.Fatalf("Failed to get config: %s", err)
	}

	parsedCommand, err := packageManager.ParseCommand(args)
	if err != nil {
		ui.Fatalf("Failed to parse command: %s", err)
	}

	packageResolverConfig := packagemanager.NewDefaultNpmDependencyResolverConfig()
	packageResolverConfig.IncludeTransitiveDependencies = config.Transitive
	packageResolverConfig.TransitiveDepth = config.TransitiveDepth
	packageResolverConfig.IncludeDevDependencies = config.IncludeDevDependencies

	packageResolver, err := packagemanager.NewNpmDependencyResolver(packageResolverConfig)
	if err != nil {
		ui.Fatalf("Failed to create dependency resolver: %s", err)
	}

	return flows.Common(packageManager, packageResolver, config).Run(ctx, args, parsedCommand)
}
