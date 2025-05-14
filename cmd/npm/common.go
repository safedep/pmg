package npm

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/guard"
	"github.com/safedep/pmg/packagemanager"
)

func executeCommonFlow(pm packagemanager.PackageManager, args []string) error {
	packageResolver, err := packagemanager.NewNpmDependencyResolver(packagemanager.NewDefaultNpmDependencyResolverConfig())
	if err != nil {
		return fmt.Errorf("failed to create npm dependency resolver: %w", err)
	}

	proxy, err := guard.NewPackageManagerGuard(guard.PackageManagerGuardConfig{},
		pm, packageResolver, []analyzer.Analyzer{})
	if err != nil {
		return fmt.Errorf("failed to create package manager guard: %w", err)
	}

	return proxy.Run(context.Background(), args)
}

func executeNpmFlow(args []string) error {
	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultNpmPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create npm package manager: %w", err)
	}

	return executeCommonFlow(packageManager, args)
}

func executePnpmFlow(args []string) error {
	packageManager, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultPnpmPackageManagerConfig())
	if err != nil {
		return fmt.Errorf("failed to create pnpm package manager: %w", err)
	}

	return executeCommonFlow(packageManager, args)
}
