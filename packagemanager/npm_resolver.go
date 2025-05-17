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

	// MaxConcurrency limits the number of concurrent goroutines used for dependency resolution
	MaxConcurrency int
}

func NewDefaultNpmDependencyResolverConfig() NpmDependencyResolverConfig {
	return NpmDependencyResolverConfig{
		IncludeDevDependencies:        false,
		IncludeTransitiveDependencies: true,
		TransitiveDepth:               5,
		FailFast:                      false,
		MaxConcurrency:                10,
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
	resolver := newDependencyResolver(r.registry, dependencyResolverConfig{
		IncludeDevDependencies:        r.config.IncludeDevDependencies,
		IncludeTransitiveDependencies: r.config.IncludeTransitiveDependencies,
		TransitiveDepth:               r.config.TransitiveDepth,
		FailFast:                      r.config.FailFast,
		MaxConcurrency:                r.config.MaxConcurrency,
	}, npmCleanVersion)

	return resolver.resolveDependencies(ctx, packageVersion)
}
