package packagemanager

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

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
	pypiVersionSpecResolverFn := func(packageName, version string) string {
		ver, err := pipGetMatchingVersion(packageName, version)
		// fmt.Printf("Resolved %s for %s to %s\n", version, packageName, ver)
		if err != nil {
			log.Debugf("error getting matching version for %s@%s", packageName, version)
			return ""
		}
		return ver
	}

	pypiDependencyResolverFn := func(packageName, version string) (*packageregistry.PackageDependencyList, error) {
		resolvedDependencies, err := getPypiPackageDependencies(packageName, version)
		if err != nil {
			return nil, err
		}
		dependencies := make([]packageregistry.PackageDependencyInfo, 0)
		for _, dep := range resolvedDependencies {
			dependencies = append(dependencies, packageregistry.PackageDependencyInfo{
				Name:        dep.PackageNameExtra,
				VersionSpec: dep.VersionSpec,
			})
		}

		return &packageregistry.PackageDependencyList{
			Dependencies: dependencies,
		}, nil
	}

	// Python treats package names with '-' and '_' as equivalent (e.g., 'my-package' and 'my_package' refer to the same package)
	packageKeyFn := func(pkg *packagev1.PackageVersion) string {
		normalizedName := normalizePackageName(pkg.Package.Name)
		return fmt.Sprintf("%s@%s", normalizedName, pkg.Version)
	}

	resolver := newDependencyResolver(p.registry, dependencyResolverConfig{
		IncludeDevDependencies:        p.config.IncludeDevDependencies,
		IncludeTransitiveDependencies: p.config.IncludeTransitiveDependencies,
		TransitiveDepth:               p.config.TransitiveDepth,
		FailFast:                      p.config.FailFast,
		MaxConcurrency:                p.config.MaxConcurrency,
	}, pypiVersionSpecResolverFn, pypiDependencyResolverFn, packageKeyFn)

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

type pypiPackage struct {
	Info     pypiPackageInfo `json:"info"`
	Releases map[string]any  `json:"releases"`
}

type PyPIDependencySpec struct {
	// PackageNameExtra is the package name including any direct extras in brackets
	// Example: "uvicorn[standard]"
	PackageNameExtra string

	// VersionSpec is the version constraint for the package
	// Example: ">=0.12.0", "==1.0.0", ">=2.0,<3.0"
	VersionSpec string

	// Extra is the conditional extra marker that defines when this dependency applies
	// Example: "all" from "; extra == \"all\""
	Extra string
}

type pypiPackageInfo struct {
	Name            string   `json:"name"`
	Description     string   `json:"summary"`
	LatestVersion   string   `json:"version"`
	PackageURL      string   `json:"package_url"`
	Author          string   `json:"author"`
	AuthorEmail     string   `json:"author_email"`
	Maintainer      string   `json:"maintainer"`
	MaintainerEmail string   `json:"maintainer_email"`
	RequiresDist    []string `json:"requires_dist"`
}

func getPypiPackageDependencies(packageName, version string) ([]PyPIDependencySpec, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", packageName, version)

	res, err := http.Get(url)
	if err != nil {
		return nil, ErrFailedToFetchPackage
	}

	if res.StatusCode == 404 {
		return nil, ErrPackageNotFound
	}

	if res.StatusCode != 200 {
		return nil, ErrFailedToFetchPackage
	}
	defer res.Body.Close()

	var pypipkg pypiPackage
	err = json.NewDecoder(res.Body).Decode(&pypipkg)
	if err != nil {
		return nil, ErrFailedToParsePackage
	}

	pkgDeps := make([]PyPIDependencySpec, 0, len(pypipkg.Info.RequiresDist))

	for _, dep := range pypipkg.Info.RequiresDist {
		name, version, extra := pypiParseDependency(dep)

		// Skip dependencies with extras/conditions to avoid resolution issues
		if extra == "" {
			pkgDeps = append(pkgDeps, PyPIDependencySpec{
				PackageNameExtra: name,
				VersionSpec:      version,
				Extra:            extra,
			})
		}
	}

	return pkgDeps, nil
}

// pypiParseDependency parses a PyPI dependency specification, handling both package extras
// and conditional dependencies. Keeps extras as part of the package name.
// Example: "uvicorn[standard]>=0.12.0; extra == \"all\"" returns ("uvicorn[standard]", ">=0.12.0", "all")
func pypiParseDependency(input string) (string, string, string) {
	// Split line by ';' to separate version and markers
	parts := strings.SplitN(input, ";", 2)
	mainPart := strings.TrimSpace(parts[0])

	// Regex to match the first occurrence of version operators
	// Using lookahead to ensure we match standalone operators
	operatorRegex := regexp.MustCompile(`(==|>=|<=|!=|>|<|~=)(?:\d|$)`)
	match := operatorRegex.FindStringIndex(mainPart)

	var name, version string
	if match != nil {
		// Everything before the operator is the name
		name = strings.TrimSpace(mainPart[:match[0]])
		// Remove trailing parentheses from name if present
		name = strings.TrimRight(name, " (")

		// Everything from the operator onwards is the version spec
		version = strings.TrimSpace(mainPart[match[0]:])
		// Remove parentheses from version spec if present
		version = strings.Trim(version, "()")
	} else {
		// No version operator found
		name = mainPart
		version = ""
	}

	// Extract extra marker if present
	var extra string
	if len(parts) == 2 {
		extraRe := regexp.MustCompile(`extra\s*==\s*["']([^"']+)["']`)
		if match := extraRe.FindStringSubmatch(parts[1]); len(match) == 2 {
			extra = match[1]
		}
	}

	return name, version, extra
}

func pipGetMatchingVersion(packageName, versionConstraint string) (string, error) {
	// Already a exact version
	if strings.HasPrefix(versionConstraint, "==") {
		return versionConstraint, nil
	}

	// Handle compatible release operator
	if strings.HasPrefix(versionConstraint, "~=") {
		versionConstraint = pipConvertCompatibleRelease(versionConstraint)
	}
	// Handle empty version constraint
	if versionConstraint == "" {
		// Get latest version
		registry, err := packageregistry.NewPypiAdapter()
		if err != nil {
			return "", fmt.Errorf("failed to create pypi adapter: %w", err)
		}

		pd, err := registry.PackageDiscovery()
		if err != nil {
			return "", fmt.Errorf("failed to get package discovery: %w", err)
		}

		pkg, err := pd.GetPackage(packageName)
		if err != nil {
			return "", err
		}

		return pkg.LatestVersion, nil
	}

	registry, err := packageregistry.NewPypiAdapter()
	if err != nil {
		return "", fmt.Errorf("failed to create pypi adapter: %w", err)
	}

	pd, err := registry.PackageDiscovery()
	if err != nil {
		return "", fmt.Errorf("failed to get package discovery: %w", err)
	}

	// Get package info from PyPI
	pkg, err := pd.GetPackage(packageName)
	if err != nil {
		return "", err
	}

	// Parse version constraint
	constraint, err := semver.NewConstraint(versionConstraint)
	if err != nil {
		return "", fmt.Errorf("invalid version constraint: %w", err)
	}

	// Get valid versions and find best match
	bestMatch, err := findBestMatchingVersion(pkg.Versions, constraint)
	if err != nil {
		return "", fmt.Errorf("no version matches constraint %q: %w", versionConstraint, err)
	}

	return bestMatch.Original(), nil
}

func findBestMatchingVersion(releases []packageregistry.PackageVersionInfo, constraint *semver.Constraints) (*semver.Version, error) {
	if len(releases) == 0 {
		return nil, fmt.Errorf("no versions available")
	}

	var bestMatch *semver.Version
	// We'll iterate once through all versions
	for _, v := range releases {
		ver, err := semver.NewVersion(v.Version)
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

func normalizePackageName(name string) string {
	// Convert to lowercase
	name = strings.ToLower(name)

	// Replace any sequence of [-_.] with a single hyphen
	re := regexp.MustCompile(`[-_.]+`)
	name = re.ReplaceAllString(name, "-")

	return name
}
