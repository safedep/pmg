package npm

import (
	"context"
	_ "embed"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewPnpmCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "pnpm [action] [package]",
		Short:              "Guard pnpm package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executePnpmFlow(cmd.Context(), args)
			if err != nil {
				log.Errorf("Failed to execute pnpm flow: %s", err)
			}

			return nil
		},
	}
}

func executePnpmFlow(ctx context.Context, args []string) error {
	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultPnpmPackageManagerConfig())
	if err != nil {
		ui.Fatalf("Failed to create pnpm package manager proxy: %s", err)
	}
	config, err := config.FromContext(ctx)
	if err != nil {
		ui.Fatalf("Failed to get config: %s", err)
	}

	packageResolverConfig := packagemanager.NewDefaultNpmDependencyResolverConfig()
	packageResolverConfig.IncludeTransitiveDependencies = config.Transitive
	packageResolverConfig.TransitiveDepth = config.TransitiveDepth
	packageResolverConfig.IncludeDevDependencies = config.IncludeDevDependencies

	packageResolver, err := packagemanager.NewNpmDependencyResolver(packageResolverConfig)

	return flows.Common(packageManager, packageResolver, config).Run(ctx, args)
}
