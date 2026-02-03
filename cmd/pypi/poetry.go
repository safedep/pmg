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
		return fmt.Errorf("failed to create poetry package manager: %w", err)
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

	if config.IsProxyModeEnabled() {
		return flows.ProxyFlow(packageManager, packageResolver).Run(ctx, args, parsedCommand)
	}

	return flows.Common(packageManager, packageResolver).Run(ctx, args, parsedCommand)
}
