package packagemanager

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/Masterminds/semver"
	"github.com/safedep/dry/log"
	"github.com/safedep/dry/packageregistry"
)

type PyPiDependencyResolverConfig struct {
	IncludeDevDependencies        bool
	IncludeTransitiveDependencies bool
	TransitiveDepth               int

	// FailFast will stop resolving dependencies after the first error
	FailFast bool

	// MaxConcurrency limits the number of concurrent goroutines used for dependency resolution
	MaxConcurrency int
}

func NewDefaultPypiDependencyResolverConfig() PyPiDependencyResolverConfig {
	return PyPiDependencyResolverConfig{
		IncludeDevDependencies:        false,
		IncludeTransitiveDependencies: true,
		TransitiveDepth:               5,
		FailFast:                      false,
		MaxConcurrency:                10,
	}
}

type pypiDependencyResolver struct {
	registry packageregistry.Client
	config   PyPiDependencyResolverConfig
}

var _ PackageResolver = &pypiDependencyResolver{}

func NewPypiDependencyResolver(config PyPiDependencyResolverConfig) (*pypiDependencyResolver, error) {
	client, err := packageregistry.NewPypiAdapter()
	if err != nil {
		return nil, fmt.Errorf("failed to create pypi adapter: %w", err)
	}

	return &pypiDependencyResolver{
		config:   config,
		registry: client,
	}, nil
}

func (p *pypiDependencyResolver) ResolveDependencies(ctx context.Context, pkg *packagev1.PackageVersion) ([]*packagev1.PackageVersion, error) {
	resolver := newDependencyResolver(p.registry, dependencyResolverConfig{
		IncludeDevDependencies:        p.config.IncludeDevDependencies,
		IncludeTransitiveDependencies: p.config.IncludeTransitiveDependencies,
		TransitiveDepth:               p.config.TransitiveDepth,
		FailFast:                      p.config.FailFast,
		MaxConcurrency:                p.config.MaxConcurrency,
	})

	return resolver.resolveDependencies(ctx, pkg)
}

func (p *pypiDependencyResolver) ResolveLatestVersion(ctx context.Context, pkg *packagev1.Package) (*packagev1.PackageVersion, error) {
	pd, err := p.registry.PackageDiscovery()
	if err != nil {
		return nil, fmt.Errorf("failed to get package discovery: %w", err)
	}

	pkgInfo, err := pd.GetPackage(pkg.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get package: %w", err)
	}
	log.Debugf("Resolved pypi/%s to latest version %s", pkg.Name, pkgInfo.LatestVersion)

	return &packagev1.PackageVersion{
		Package: pkg,
		Version: pkgInfo.LatestVersion,
	}, nil
}

// PyPIPackage represents the package information from PyPI
type PyPIPackage struct {
	Releases map[string]any `json:"releases"`
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func pipGetMatchingVersion(packageName, versionConstraint string) (string, error) {
	// Already a exact version
	if strings.HasPrefix(versionConstraint, "==") {
		return versionConstraint, nil
	}

	// Handle compatible release operator
	if strings.HasPrefix(versionConstraint, "~=") {
		versionConstraint = pipConvertCompatibleRelease(versionConstraint)
	}

	// Get package info from PyPI
	pkg, err := pipFetchPackageVersionsInfo(packageName)
	if err != nil {
		return "", err
	}

	// Parse version constraint
	constraint, err := semver.NewConstraint(versionConstraint)
	if err != nil {
		return "", fmt.Errorf("invalid version constraint: %w", err)
	}

	// Get valid versions and find best match
	bestMatch, err := findBestMatchingVersion(pkg.Releases, constraint)
	if err != nil {
		return "", fmt.Errorf("no version matches constraint %q: %w", versionConstraint, err)
	}

	return bestMatch.Original(), nil
}

// pipFetchPackageVersionsInfo retrieves package information from PyPI
func pipFetchPackageVersionsInfo(packageName string) (*PyPIPackage, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", packageName)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("package not found or HTTP error: %d", resp.StatusCode)
	}

	var pypiPkg PyPIPackage
	if err := json.NewDecoder(resp.Body).Decode(&pypiPkg); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &pypiPkg, nil
}

func findBestMatchingVersion(releases map[string]any, constraint *semver.Constraints) (*semver.Version, error) {
	if len(releases) == 0 {
		return nil, fmt.Errorf("no versions available")
	}

	var bestMatch *semver.Version
	// We'll iterate once through all versions
	for v := range releases {
		ver, err := semver.NewVersion(v)
		if err != nil {
			continue // Skip invalid versions
		}

		// Update bestMatch if this version is higher and matches constraint
		if constraint.Check(ver) && (bestMatch == nil || ver.GreaterThan(bestMatch)) {
			bestMatch = ver
		}
	}

	if bestMatch == nil {
		return nil, fmt.Errorf("no version matches constraint")
	}
	return bestMatch, nil
}
