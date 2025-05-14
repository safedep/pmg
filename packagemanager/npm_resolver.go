package packagemanager

import (
	"context"
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/dry/packageregistry"
)

type NpmDependencyResolverConfig struct {
	IncludeDevDependencies        bool
	IncludeTransitiveDependencies bool
	TransitiveDepth               int

	// FailFast will stop resolving dependencies after the first error
	FailFast bool
}

func NewDefaultNpmDependencyResolverConfig() NpmDependencyResolverConfig {
	return NpmDependencyResolverConfig{
		IncludeDevDependencies:        true,
		IncludeTransitiveDependencies: true,
		TransitiveDepth:               5,
		FailFast:                      false,
	}
}

type npmDependencyResolver struct {
	registry packageregistry.Client
	config   NpmDependencyResolverConfig
}

var _ PackageResolver = &npmDependencyResolver{}

func NewNpmDependencyResolver(config NpmDependencyResolverConfig) (*npmDependencyResolver, error) {
	client, err := packageregistry.NewNpmAdapter()
	if err != nil {
		return nil, fmt.Errorf("failed to create npm adapter: %w", err)
	}

	return &npmDependencyResolver{
		registry: client,
		config:   config,
	}, nil
}

func (r *npmDependencyResolver) ResolveLatestVersion(ctx context.Context,
	pkg *packagev1.Package) (*packagev1.PackageVersion, error) {
	pd, err := r.registry.PackageDiscovery()
	if err != nil {
		return nil, fmt.Errorf("failed to get package discovery: %w", err)
	}

	pkgInfo, err := pd.GetPackage(pkg.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get package: %w", err)
	}

	log.Debugf("Resolved npm/%s to latest version %s", pkg.Name, pkgInfo.LatestVersion)

	return &packagev1.PackageVersion{
		Package: pkg,
		Version: pkgInfo.LatestVersion,
	}, nil
}

// TODO: Refactor this into a generic dependency resolver that depends on
// package registry client
func (r *npmDependencyResolver) ResolveDependencies(ctx context.Context,
	packageVersion *packagev1.PackageVersion) ([]*packagev1.PackageVersion, error) {
	pd, err := r.registry.PackageDiscovery()
	if err != nil {
		return nil, fmt.Errorf("failed to get package discovery: %w", err)
	}

	// Track visited packages to avoid cycles
	visitedPackages := make(map[string]bool)

	// Result collection
	dependencies := make([]*packagev1.PackageVersion, 0)

	// Start recursive resolution
	err = r.resolvePackageDependenciesRecursive(ctx, pd, packageVersion, 0, visitedPackages, &dependencies)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dependencies: %w", err)
	}

	return dependencies, nil
}

// resolvePackageDependenciesRecursive resolves dependencies for a package version recursively
func (r *npmDependencyResolver) resolvePackageDependenciesRecursive(
	ctx context.Context,
	pd packageregistry.PackageDiscovery,
	packageVersion *packagev1.PackageVersion,
	depth int,
	visitedPackages map[string]bool,
	result *[]*packagev1.PackageVersion) error {

	ff := func(err error) error {
		if r.config.FailFast {
			return err
		}

		log.Warnf("error resolving package dependencies: %w", err)
		return nil
	}

	// Check depth limit
	if depth > r.config.TransitiveDepth {
		return ff(fmt.Errorf("exceeded maximum transitive depth of %d", r.config.TransitiveDepth))
	}

	// Skip if already visited
	packageKey := r.packageKey(packageVersion)
	if visitedPackages[packageKey] {
		return nil
	}

	// Mark as visited
	visitedPackages[packageKey] = true

	log.Debugf("resolving dependencies for %s@%s", packageVersion.Package.Name, packageVersion.Version)

	// Get dependencies for the current package
	dependencyList, err := pd.GetPackageDependencies(packageVersion.Package.Name, packageVersion.Version)
	if err != nil {
		return ff(fmt.Errorf("failed to get package dependencies: %w", err))
	}

	// Collect all dependencies (and optionally dev dependencies)
	dependencies := dependencyList.Dependencies
	if r.config.IncludeDevDependencies {
		dependencies = append(dependencies, dependencyList.DevDependencies...)
	}

	// Create package version objects for all dependencies
	resolvedDependencies := make([]*packagev1.PackageVersion, 0, len(dependencies))
	for _, dependency := range dependencies {
		resolvedDependencies = append(resolvedDependencies, &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				Name:      dependency.Name,
			},
			Version: npmCleanVersion(dependency.VersionSpec),
		})
	}

	// Add all resolved dependencies to the result
	*result = append(*result, resolvedDependencies...)

	// Process transitive dependencies if enabled
	if r.config.IncludeTransitiveDependencies {
		for _, dependency := range resolvedDependencies {
			err := r.resolvePackageDependenciesRecursive(ctx, pd, dependency, depth+1, visitedPackages, result)
			if err != nil {
				return ff(fmt.Errorf("failed to resolve transitive dependency: %w", err))
			}
		}
	}

	return nil
}

func (r *npmDependencyResolver) packageKey(pkg *packagev1.PackageVersion) string {
	return fmt.Sprintf("%s@%s", pkg.Package.Name, pkg.Version)
}
