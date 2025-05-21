package packagemanager

import (
	"context"
	"fmt"
	"slices"
	"sync"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/dry/packageregistry"
)

// Contract for a function that implements ecosystem specific version
// resolver from a version range specification.
type versionSpecResolver func(packageName, version string) string

type dependencyResolverConfig struct {
	IncludeDevDependencies        bool
	IncludeTransitiveDependencies bool
	TransitiveDepth               int
	FailFast                      bool
	MaxConcurrency                int
}

type dependencyResolver struct {
	client              packageregistry.Client
	config              dependencyResolverConfig
	mutex               sync.Mutex
	versionSpecResolver versionSpecResolver
}

func newDependencyResolver(client packageregistry.Client, config dependencyResolverConfig,
	versionSpecResolver versionSpecResolver) *dependencyResolver {
	if config.MaxConcurrency <= 0 {
		config.MaxConcurrency = 10
	}

	if versionSpecResolver == nil {
		// Default version spec resolver
		versionSpecResolver = func(packageName, version string) string {
			return version
		}
	}

	return &dependencyResolver{
		client:              client,
		config:              config,
		versionSpecResolver: versionSpecResolver,
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

	// Start concurrent resolution
	err = r.resolvePackageDependenciesConcurrent(ctx, pd, packageVersion, 0, visitedPackages, &dependencies)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dependencies: %w", err)
	}

	return dependencies, nil
}

// resolvePackageDependenciesConcurrent resolves dependencies for a package version concurrently
func (r *dependencyResolver) resolvePackageDependenciesConcurrent(
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

		log.Warnf("error resolving package dependencies: %s", err)
		return nil
	}

	// Check depth limit
	if depth > r.config.TransitiveDepth {
		return ff(fmt.Errorf("exceeded maximum transitive depth of %d", r.config.TransitiveDepth))
	}

	// Skip if already visited
	packageKey := r.packageKey(packageVersion)

	alreadyVisited := false
	r.synchronize(func() {
		alreadyVisited = visitedPackages[packageKey]
	})

	if alreadyVisited {
		return nil
	}

	// Mark the current package as visited
	r.synchronize(func() {
		visitedPackages[packageKey] = true
	})

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

	// Create package version objects for all dependencies and clean versions
	resolvedDependencies := make([]*packagev1.PackageVersion, 0, len(dependencies))
	for _, dependency := range dependencies {
		resolvedDependencies = append(resolvedDependencies, &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Ecosystem: packageVersion.GetPackage().GetEcosystem(),
				Name:      dependency.Name,
			},
			Version: r.versionSpecResolver(dependency.Name, dependency.VersionSpec),
		})
	}

	// Add resolved dependencies to the result
	r.synchronize(func() {
		for _, dependency := range resolvedDependencies {
			if !slices.Contains(*result, dependency) {
				*result = append(*result, dependency)
			}
		}
	})

	// Process transitive dependencies if enabled and depth limit not reached
	if r.config.IncludeTransitiveDependencies && depth < r.config.TransitiveDepth && len(resolvedDependencies) > 0 {
		// Create worker pool using semaphore pattern
		semaphore := make(chan struct{}, r.config.MaxConcurrency)
		errCh := make(chan error, len(resolvedDependencies))
		var wg sync.WaitGroup

		for _, dependency := range resolvedDependencies {
			wg.Add(1)

			go func(dep *packagev1.PackageVersion) {
				defer wg.Done()

				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				err := r.resolvePackageDependenciesConcurrent(ctx, pd, dep, depth+1, visitedPackages, result)
				if err != nil {
					errCh <- err
				}
			}(dependency)
		}

		// Wait for all goroutines to finish
		wg.Wait()
		close(errCh)

		// Check for errors
		for err := range errCh {
			return ff(fmt.Errorf("failed to resolve transitive dependency: %w", err))
		}
	}

	return nil
}

func (r *dependencyResolver) packageKey(pkg *packagev1.PackageVersion) string {
	return fmt.Sprintf("%s@%s", pkg.Package.Name, pkg.Version)
}

func (r *dependencyResolver) synchronize(fn func()) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	fn()
}
