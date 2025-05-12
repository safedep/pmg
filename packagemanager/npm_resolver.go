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
		TransitiveDepth:               100,
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

func (r *npmDependencyResolver) ResolveDependencies(ctx context.Context,
	packageVersion *packagev1.PackageVersion) ([]*packagev1.PackageVersion, error) {
	pd, err := r.registry.PackageDiscovery()
	if err != nil {
		return nil, fmt.Errorf("failed to get package discovery: %w", err)
	}

	// inputQueue is the queue of package versions to resolve
	inputQueue := make([]*packagev1.PackageVersion, 0)

	// outputQueue is the queue of resolved package versions
	outputQueue := make([]*packagev1.PackageVersion, 0)

	// Start with the initial package version to resolve
	inputQueue = append(inputQueue, packageVersion)

	resolutionDepth := 0
	visitedPackages := make(map[string]bool)

	for {
		if len(inputQueue) == 0 {
			break
		}

		if resolutionDepth > r.config.TransitiveDepth {
			return nil, fmt.Errorf("exceeded maximum transitive depth of %d", r.config.TransitiveDepth)
		}

		packageVersion = inputQueue[0]
		inputQueue = inputQueue[1:]

		// Skip if we've already visited this package version
		// Like npm, we will reuse an existing version instead of considering
		// every single version of a dependency. This is a heuristic. We are not
		// actually checking for compatibility here like npm does
		packageKey := fmt.Sprintf("%s@*", packageVersion.Package.Name)
		if visitedPackages[packageKey] {
			continue
		}

		// Mark the package version as visited
		visitedPackages[packageKey] = true

		dependencyList, err := pd.GetPackageDependencies(packageVersion.Package.Name, packageVersion.Version)
		if err != nil {
			if r.config.FailFast {
				return nil, fmt.Errorf("failed to get package dependencies: %w", err)
			}

			log.Warnf("failed to get package dependencies: %s", err)
			continue
		}

		dependencies := dependencyList.Dependencies
		if r.config.IncludeDevDependencies {
			dependencies = append(dependencies, dependencyList.DevDependencies...)
		}

		resolvedPackageVersionDependencies := make([]*packagev1.PackageVersion, 0)
		for _, dependency := range dependencies {
			resolvedPackageVersionDependencies = append(resolvedPackageVersionDependencies, &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      dependency.Name,
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: npmCleanVersion(dependency.VersionSpec),
			})
		}

		outputQueue = append(outputQueue, resolvedPackageVersionDependencies...)

		if r.config.IncludeTransitiveDependencies {
			inputQueue = append(inputQueue, resolvedPackageVersionDependencies...)
		}

		resolutionDepth++
	}

	return outputQueue, nil
}
