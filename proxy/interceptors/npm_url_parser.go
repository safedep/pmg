package interceptors

import (
	"fmt"
	"strings"
)

// npmPackageInfo represents parsed package information from an NPM registry URL
type npmPackageInfo struct {
	Name      string
	Version   string
	IsTarball bool
	IsScoped  bool
}

// parseNpmRegistryURL parses an NPM registry URL path to extract package information
//
// Supported URL patterns:
// - /package                               -> {Name: "package", Version: ""}
// - /package/1.0.0                         -> {Name: "package", Version: "1.0.0"}
// - /@scope/package                        -> {Name: "@scope/package", Version: "", IsScoped: true}
// - /@scope/package/1.0.0                  -> {Name: "@scope/package", Version: "1.0.0", IsScoped: true}
// - /package/-/package-1.0.0.tgz          -> {Name: "package", Version: "1.0.0", IsTarball: true}
// - /@scope/package/-/@scope-package-1.0.0.tgz -> {Name: "@scope/package", Version: "1.0.0", IsTarball: true, IsScoped: true}
func parseNpmRegistryURL(urlPath string) (*npmPackageInfo, error) {
	// Remove leading and trailing slashes
	urlPath = strings.Trim(urlPath, "/")

	if urlPath == "" {
		return nil, fmt.Errorf("empty URL path")
	}

	// Split path into segments
	segments := strings.Split(urlPath, "/")

	// Check if this is a scoped package (starts with @)
	isScoped := len(segments) > 0 && strings.HasPrefix(segments[0], "@")

	if isScoped {
		return parseScopedPackageURL(segments)
	}

	return parseUnscopedPackageURL(segments)
}

// parseScopedPackageURL parses a scoped package URL
// Patterns:
// - [@scope, package]                    -> @scope/package
// - [@scope, package, version]           -> @scope/package@version
// - [@scope, package, -, tarball.tgz]    -> @scope/package@version (extract from tarball)
func parseScopedPackageURL(segments []string) (*npmPackageInfo, error) {
	if len(segments) < 2 {
		return nil, fmt.Errorf("invalid scoped package URL: not enough segments")
	}

	scope := segments[0]
	packageName := segments[1]
	fullName := scope + "/" + packageName

	info := &npmPackageInfo{
		Name:     fullName,
		IsScoped: true,
	}

	// Just the scoped package name: /@scope/package
	if len(segments) == 2 {
		return info, nil
	}

	// Check if this is a tarball download: /@scope/package/-/tarball.tgz
	if len(segments) == 4 && segments[2] == "-" {
		tarballName := segments[3]

		// Extract version from tarball filename
		// Format: @scope-package-1.0.0.tgz
		version, err := extractVersionFromScopedTarball(scope, packageName, tarballName)
		if err != nil {
			return nil, fmt.Errorf("failed to extract version from tarball %s: %w", tarballName, err)
		}

		info.Version = version
		info.IsTarball = true
		return info, nil
	}

	// Version metadata: /@scope/package/1.0.0
	if len(segments) == 3 {
		info.Version = segments[2]
		return info, nil
	}

	return nil, fmt.Errorf("invalid scoped package URL format: unexpected number of segments %d", len(segments))
}

// parseUnscopedPackageURL parses an unscoped package URL
// Patterns:
// - [package]                -> package
// - [package, version]       -> package@version
// - [package, -, tarball.tgz] -> package@version (extract from tarball)
func parseUnscopedPackageURL(segments []string) (*npmPackageInfo, error) {
	if len(segments) == 0 {
		return nil, fmt.Errorf("invalid unscoped package URL: no segments")
	}

	packageName := segments[0]

	info := &npmPackageInfo{
		Name:     packageName,
		IsScoped: false,
	}

	// Just the package name: /package
	if len(segments) == 1 {
		return info, nil
	}

	// Check if this is a tarball download: /package/-/package-1.0.0.tgz
	if len(segments) == 3 && segments[1] == "-" {
		tarballName := segments[2]

		// Extract version from tarball filename
		// Format: package-1.0.0.tgz
		version, err := extractVersionFromTarball(packageName, tarballName)
		if err != nil {
			return nil, fmt.Errorf("failed to extract version from tarball %s: %w", tarballName, err)
		}

		info.Version = version
		info.IsTarball = true
		return info, nil
	}

	// Version metadata: /package/1.0.0
	if len(segments) == 2 {
		info.Version = segments[1]
		return info, nil
	}

	return nil, fmt.Errorf("invalid unscoped package URL format: unexpected number of segments %d", len(segments))
}

// extractVersionFromTarball extracts version from a tarball filename
// Expected format: package-name-1.0.0.tgz
func extractVersionFromTarball(packageName, tarballName string) (string, error) {
	// Expected format: {packageName}-{version}.tgz
	expectedPrefix := packageName + "-"

	if !strings.HasPrefix(tarballName, expectedPrefix) {
		return "", fmt.Errorf("tarball name %s does not match package name %s", tarballName, packageName)
	}

	if !strings.HasSuffix(tarballName, ".tgz") {
		return "", fmt.Errorf("tarball name %s does not end with .tgz", tarballName)
	}

	// Extract version by removing prefix and suffix
	version := strings.TrimPrefix(tarballName, expectedPrefix)
	version = strings.TrimSuffix(version, ".tgz")

	if version == "" {
		return "", fmt.Errorf("could not extract version from tarball %s", tarballName)
	}

	return version, nil
}

// extractVersionFromScopedTarball extracts version from a scoped package tarball filename
// Expected format: @scope-package-name-1.0.0.tgz
func extractVersionFromScopedTarball(scope, packageName, tarballName string) (string, error) {
	// Expected format: {scope}-{packageName}-{version}.tgz
	// Example: @types-node-18.0.0.tgz
	scopeWithoutAt := strings.TrimPrefix(scope, "@")
	expectedPrefix := scopeWithoutAt + "-" + packageName + "-"

	if !strings.HasPrefix(tarballName, expectedPrefix) {
		return "", fmt.Errorf("tarball name %s does not match scoped package %s/%s", tarballName, scope, packageName)
	}

	if !strings.HasSuffix(tarballName, ".tgz") {
		return "", fmt.Errorf("tarball name %s does not end with .tgz", tarballName)
	}

	// Extract version by removing prefix and suffix
	version := strings.TrimPrefix(tarballName, expectedPrefix)
	version = strings.TrimSuffix(version, ".tgz")

	if version == "" {
		return "", fmt.Errorf("could not extract version from tarball %s", tarballName)
	}

	return version, nil
}
