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

func NewNpxCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "npx [package] [action]",
		Short:              "Guard npx package executor",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeNpxFlow(cmd.Context(), args)
			if err != nil {
				ui.ErrorExit(err)
			}

			return nil
		},
	}
}

func executeNpxFlow(ctx context.Context, args []string) error {
	analytics.TrackCommandNpx()
	packageExecutor, err := packagemanager.NewNpmPackageExecutor(packagemanager.DefaultNpxPackageExecutorConfig())
	if err != nil {
		return fmt.Errorf("failed to create npx package executor proxy: %w", err)
	}

	config := config.Get()
	parsedCommand, err := packageExecutor.ParseCommand(args)
	if err != nil {
		return fmt.Errorf("failed to parse command: %w", err)
	}

	packageResolverConfig := packagemanager.NewDefaultNpmDependencyResolverConfig()
	packageResolverConfig.IncludeTransitiveDependencies = config.Config.Transitive
	packageResolverConfig.TransitiveDepth = config.Config.TransitiveDepth
	packageResolverConfig.IncludeDevDependencies = config.Config.IncludeDevDependencies

	packageResolver, err := packagemanager.NewNpmDependencyResolver(packageResolverConfig)
	if err != nil {
		return fmt.Errorf("failed to create dependency resolver: %w", err)
	}

	hooks := []flows.Hook{flows.NewSandboxPolicyHook()}

	if config.Config.ExperimentalProxyMode {
		return flows.ProxyFlow(packageExecutor, packageResolver, hooks).Run(ctx, args, parsedCommand)
	}

	return flows.Common(packageExecutor, packageResolver, hooks).Run(ctx, args, parsedCommand)
}
