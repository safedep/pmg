package npm

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/guard"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
)

func executeCommonFlow(ctx context.Context, config config.Config, pm packagemanager.PackageManager, args []string) error {
	packageResolverConfig := packagemanager.NewDefaultNpmDependencyResolverConfig()
	packageResolverConfig.IncludeTransitiveDependencies = config.Transitive
	packageResolverConfig.TransitiveDepth = config.TransitiveDepth

	packageResolver, err := packagemanager.NewNpmDependencyResolver(packageResolverConfig)
	if err != nil {
		return fmt.Errorf("failed to create npm dependency resolver: %w", err)
	}

	malysisQueryAnalyzer, err := analyzer.NewMalysisQueryAnalyzer(analyzer.MalysisQueryAnalyzerConfig{})
	if err != nil {
		return fmt.Errorf("failed to create malysis query analyzer: %w", err)
	}

	interaction := guard.PackageManagerGuardInteraction{
		SetStatus:                ui.SetStatus,
		ClearStatus:              ui.ClearStatus,
		GetConfirmationOnMalware: ui.GetConfirmationOnMalware,
		Block:                    ui.Block,
	}

	proxy, err := guard.NewPackageManagerGuard(guard.DefaultPackageManagerGuardConfig(),
		pm, packageResolver, []analyzer.MalysisAnalyzer{malysisQueryAnalyzer}, interaction)
	if err != nil {
		return fmt.Errorf("failed to create package manager guard: %w", err)
	}

	return proxy.Run(ctx, args)
}

func executeNpmFlow(ctx context.Context, config config.Config, args []string) error {
	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultNpmPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create npm package manager: %w", err)
	}

	return executeCommonFlow(ctx, config, packageManager, args)
}

func executePnpmFlow(ctx context.Context, config config.Config, args []string) error {
	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultPnpmPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create pnpm package manager: %w", err)
	}

	return executeCommonFlow(ctx, config, packageManager, args)
}
