package pypi

import (
	"context"
	"fmt"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/spf13/cobra"
)

func NewPipCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "pip [action] [package]",
		Short:              "Guard pip package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executePipFlow(cmd.Context(), args)
			if err != nil {
				log.Errorf("Failed to execute pip flow: %s", err)
			}

			return nil
		},
	}
}

func executePipFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandPip()
	packageManager, err := packagemanager.NewPipPackageManager(packagemanager.DefaultPipPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create pip package manager: %w", err)
	}

	config, err := config.FromContext(ctx)
	if err != nil {
		ui.Fatalf("Failed to get config: %s", err)
	}

	parsedCommand, err := packageManager.ParseCommand(args)
	if err != nil {
		return fmt.Errorf("failed to parse command: %w", err)
	}

	// Parse the args right here
	packageResolverConfig := packagemanager.NewDefaultPypiDependencyResolverConfig()
	packageResolverConfig.IncludeTransitiveDependencies = config.Transitive
	packageResolverConfig.TransitiveDepth = config.TransitiveDepth
	packageResolverConfig.IncludeDevDependencies = config.IncludeDevDependencies
	packageResolverConfig.PackageInstallTargets = parsedCommand.InstallTargets

	packageResolver, err := packagemanager.NewPypiDependencyResolver(packageResolverConfig)
	if err != nil {
		ui.Fatalf("Failed to create dependency resolver: %s", err)
	}

	return flows.Common(packageManager, packageResolver, config).Run(ctx, args, parsedCommand)
}
