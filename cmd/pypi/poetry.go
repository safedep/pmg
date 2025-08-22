package pypi

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

func NewPoetryCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "poetry [action] [package]",
		Short:              "Guard poetry package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executePoetryFlow(cmd.Context(), args)
			if err != nil {
				ui.ErrorExit(err)
			}

			return nil
		},
	}
}

func executePoetryFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandPoetry()
	packageManager, err := packagemanager.NewPypiPackageManager(packagemanager.DefaultPoetryPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create uv package manager: %w", err)
	}

	config, err := config.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	parsedCommand, err := packageManager.ParseCommand(args)
	if err != nil {
		return fmt.Errorf("failed to parse command: %w", err)
	}

	packageResolverConfig := packagemanager.NewDefaultPypiDependencyResolverConfig()
	packageResolverConfig.IncludeTransitiveDependencies = config.Transitive
	packageResolverConfig.TransitiveDepth = config.TransitiveDepth
	packageResolverConfig.IncludeDevDependencies = config.IncludeDevDependencies
	packageResolverConfig.PackageInstallTargets = parsedCommand.InstallTargets

	packageResolver, err := packagemanager.NewPypiDependencyResolver(packageResolverConfig)
	if err != nil {
		return fmt.Errorf("failed to create dependency resolver: %w", err)
	}

	return flows.Common(packageManager, packageResolver, config).Run(ctx, args, parsedCommand)
}
