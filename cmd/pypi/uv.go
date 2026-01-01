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

func NewUvCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "uv [action] [package]",
		Short:              "Guard uv package manager",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeUvFlow(cmd.Context(), args)
			if err != nil {
				ui.ErrorExit(err)
			}

			return nil
		},
	}
}

func executeUvFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandUv()
	packageManager, err := packagemanager.NewPypiPackageManager(packagemanager.DefaultUvPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create uv package manager: %w", err)
	}

	config := config.Get()
	parsedCommand, err := packageManager.ParseCommand(args)
	if err != nil {
		return fmt.Errorf("failed to parse command: %w", err)
	}

	packageResolverConfig := packagemanager.NewDefaultPypiDependencyResolverConfig()
	packageResolverConfig.IncludeTransitiveDependencies = config.Config.Transitive
	packageResolverConfig.TransitiveDepth = config.Config.TransitiveDepth
	packageResolverConfig.IncludeDevDependencies = config.Config.IncludeDevDependencies
	packageResolverConfig.PackageInstallTargets = parsedCommand.InstallTargets

	packageResolver, err := packagemanager.NewPypiDependencyResolver(packageResolverConfig)
	if err != nil {
		return fmt.Errorf("failed to create dependency resolver: %w", err)
	}

	return flows.Common(packageManager, packageResolver).Run(ctx, args, parsedCommand)
}
