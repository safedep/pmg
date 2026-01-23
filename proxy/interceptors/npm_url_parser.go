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

// npmRegistryURLParser defines the interface for parsing registry-specific URLs
type npmRegistryURLParser interface {
	ParseURL(urlPath string) (*npmPackageInfo, error)
}

type npmParser struct{}

// parseNpmRegistryURL parses standard NPM registry URL paths (registry.npmjs.org, registry.yarnpkg.com)
// This function handles the standard npm registry URL format.
//
// Supported URL patterns:
// - /package                               -> {Name: "package", Version: ""}
// - /package/1.0.0                         -> {Name: "package", Version: "1.0.0"}
// - /@scope/package                        -> {Name: "@scope/package", Version: "", IsScoped: true}
// - /@scope/package/1.0.0                  -> {Name: "@scope/package", Version: "1.0.0", IsScoped: true}
// - /package/-/package-1.0.0.tgz          -> {Name: "package", Version: "1.0.0", IsTarball: true}
// - /@scope/package/-/@scope-package-1.0.0.tgz -> {Name: "@scope/package", Version: "1.0.0", IsTarball: true, IsScoped: true}
func (n npmParser) ParseURL(urlPath string) (*npmPackageInfo, error) {
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

type githubParser struct{}

// ParseURL implements RegistryURLParser for GitHub npm registry
func (g githubParser) ParseURL(urlPath string) (*npmPackageInfo, error) {
	// For now, just allow all GitHub npm registry requests through without analysis
	// TODO: Implement proper GitHub npm registry URL parsing when analysis is enabled
	// GitHub URLs follow patterns:
	// - /download/@owner/package/version/hash.tgz -> {Name: "package", Version: "1.0.0", IsTarball: true}
	// - /@owner/package (metadata requests)
	return &npmPackageInfo{
		IsTarball: false, // Mark as non-tarball to skip analysis
	}, nil
}

type githubBlobParser struct{}

// ParseURL implements RegistryURLParser for GitHub blob storage
func (g githubBlobParser) ParseURL(urlPath string) (*npmPackageInfo, error) {
	// For now, just allow all GitHub blob storage requests through without analysis
	// TODO: Implement proper GitHub blob storage URL parsing when analysis is enabled
	// Pattern: /npmregistryv2prod/blobs/{blob_id}/{package_name}/{version}/***
	return &npmPackageInfo{
		IsTarball: false, // Mark as non-tarball to skip analysis
	}, nil
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
// NPM registry uses two different formats for scoped package tarballs:
// Format 1: {scope}-{package}-{version}.tgz (e.g., types-node-18.0.0.tgz for @types/node)
// Format 2: {package}-{version}.tgz (e.g., studio-core-licensed-0.0.0.tgz for @prisma/studio-core-licensed)
func extractVersionFromScopedTarball(scope, packageName, tarballName string) (string, error) {
	if !strings.HasSuffix(tarballName, ".tgz") {
		return "", fmt.Errorf("tarball name %s does not end with .tgz", tarballName)
	}

	scopeWithoutAt := strings.TrimPrefix(scope, "@")

	// Try Format 1: {scope}-{packageName}-{version}.tgz
	expectedPrefixWithScope := scopeWithoutAt + "-" + packageName + "-"
	if strings.HasPrefix(tarballName, expectedPrefixWithScope) {
		version := strings.TrimPrefix(tarballName, expectedPrefixWithScope)
		version = strings.TrimSuffix(version, ".tgz")

		if version == "" {
			return "", fmt.Errorf("could not extract version from tarball %s", tarballName)
		}

		return version, nil
	}

	// Try Format 2: {packageName}-{version}.tgz
	expectedPrefixWithoutScope := packageName + "-"
	if strings.HasPrefix(tarballName, expectedPrefixWithoutScope) {
		version := strings.TrimPrefix(tarballName, expectedPrefixWithoutScope)
		version = strings.TrimSuffix(version, ".tgz")

		if version == "" {
			return "", fmt.Errorf("could not extract version from tarball %s", tarballName)
		}

		return version, nil
	}

	return "", fmt.Errorf("tarball name %s does not match expected formats for scoped package %s/%s", tarballName, scope, packageName)
}
