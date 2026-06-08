package executors

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

func NewPipxCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "pipx [action] [package]",
		Short:              "Guard pipx package executor",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executePipxFlow(cmd.Context(), args)
			if err != nil {
				ui.ExitFromCommandError(err)
			}

			return nil
		},
	}
}

func executePipxFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandPipx()

	packageExecutor, err := packagemanager.NewPypiPackageExecutor(packagemanager.DefaultPipxPackageExecutorConfig())
	if err != nil {
		return fmt.Errorf("failed to create pipx package executor proxy: %w", err)
	}

	config := config.Get()
	parsedCommand, err := packageExecutor.ParseCommand(args)
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

	if !config.IsProxyModeEnabled() {
		return flows.Common(packageExecutor, packageResolver).Run(ctx, args, parsedCommand)
	}

	return flows.ProxyFlow(packageExecutor, packageResolver).Run(ctx, args, parsedCommand)
}
