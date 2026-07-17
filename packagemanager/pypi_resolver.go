package packagemanager

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/safedep/dry/packageregistry"
)

func pypiGetMatchingVersion(packageName, versionConstraint string) (string, error) {
	// Already a exact version
	if after, ok := strings.CutPrefix(versionConstraint, "=="); ok {
		return after, nil
	}

	// Handle compatible release operator
	if strings.HasPrefix(versionConstraint, "~=") {
		versionConstraint = pypiConvertCompatibleRelease(versionConstraint)
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
