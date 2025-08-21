package npm

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewBunCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "bun [action] [package]",
		Short:              "Guard bun package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeBunFlow(cmd.Context(), args)
			if err != nil {
				ui.ErrorExit(err)
			}

			return nil
		},
	}
}

func executeBunFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandBun()
	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultBunPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create bun package manager proxy: %w", err)
	}

	config, err := config.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	parsedCommand, err := packageManager.ParseCommand(args)
	if err != nil {
		return fmt.Errorf("failed to parse command: %w", err)
	}

	packageResolverConfig := packagemanager.NewDefaultNpmDependencyResolverConfig()
	packageResolverConfig.IncludeTransitiveDependencies = config.Transitive
	packageResolverConfig.TransitiveDepth = config.TransitiveDepth
	packageResolverConfig.IncludeDevDependencies = config.IncludeDevDependencies

	packageResolver, err := packagemanager.NewNpmDependencyResolver(packageResolverConfig)
	if err != nil {
		return fmt.Errorf("failed to create dependency resolver: %w", err)
	}

	return flows.Common(packageManager, packageResolver, config).Run(ctx, args, parsedCommand)
}
