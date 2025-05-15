package packagemanager

import (
	"context"
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/dry/packageregistry"
)

type dependencyResolverConfig struct {
	IncludeDevDependencies        bool
	IncludeTransitiveDependencies bool
	TransitiveDepth               int
	FailFast                      bool
}

type dependencyResolver struct {
	client packageregistry.Client
	config dependencyResolverConfig
}

func newDependencyResolver(client packageregistry.Client, config dependencyResolverConfig) *dependencyResolver {
	return &dependencyResolver{
		client: client,
		config: config,
	}
}

func (r *dependencyResolver) resolveDependencies(ctx context.Context,
	packageVersion *packagev1.PackageVersion) ([]*packagev1.PackageVersion, error) {
	pd, err := r.client.PackageDiscovery()
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
func (r *dependencyResolver) resolvePackageDependenciesRecursive(
	ctx context.Context,
	pd packageregistry.PackageDiscovery,
	packageVersion *packagev1.PackageVersion,
	depth int,
	visitedPackages map[string]bool,
	result *[]*packagev1.PackageVersion) error {

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

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
	if _, ok := visitedPackages[packageKey]; ok {
		return nil
	}

	// Mark the current package as visited
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
		depPackageVersion := &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				Name:      dependency.Name,
			},
			Version: npmCleanVersion(dependency.VersionSpec),
		}

		// Check if this dependency is already in the result to avoid duplicates
		depKey := r.packageKey(depPackageVersion)
		if !visitedPackages[depKey] {
			resolvedDependencies = append(resolvedDependencies, depPackageVersion)
			*result = append(*result, depPackageVersion)
			visitedPackages[depKey] = true
		}
	}

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

func (r *dependencyResolver) packageKey(pkg *packagev1.PackageVersion) string {
	return fmt.Sprintf("%s@%s", pkg.Package.Name, pkg.Version)
}
