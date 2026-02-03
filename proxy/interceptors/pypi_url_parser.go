package interceptors

import (
	"fmt"
	"regexp"
	"strings"
)

// pypiPackageInfo represents parsed package information from a PyPI registry URL
type pypiPackageInfo struct {
	name       string
	version    string
	isDownload bool   // True if this is a file download (sdist or wheel)
	fileType   string // "sdist", "wheel", or empty for non-download requests
}

// Ensure pypiPackageInfo implements packageInfo interface
var _ packageInfo = (*pypiPackageInfo)(nil)

// GetName returns the package name
func (p *pypiPackageInfo) GetName() string {
	return p.name
}

// GetVersion returns the package version
func (p *pypiPackageInfo) GetVersion() string {
	return p.version
}

// IsFileDownload returns true if this is a file download (sdist or wheel)
func (p *pypiPackageInfo) IsFileDownload() bool {
	return p.isDownload
}

// FileType returns the file type ("sdist", "wheel", or empty)
func (p *pypiPackageInfo) FileType() string {
	return p.fileType
}

// pypiFilesParser parses URLs from files.pythonhosted.org
// This is where PyPI serves package files (sdists and wheels)
type pypiFilesParser struct{}

// Ensure pypiFilesParser implements RegistryURLParser interface
var _ registryURLParser = pypiFilesParser{}

// ParseURL parses files.pythonhosted.org URL paths
// URL patterns:
// - /packages/{hash_dirs}/{filename}
// Where filename can be:
// - {name}-{version}.tar.gz (sdist)
// - {name}-{version}.zip (sdist)
// - {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl (wheel)
func (p pypiFilesParser) ParseURL(urlPath string) (packageInfo, error) {
	// Remove leading and trailing slashes
	urlPath = strings.Trim(urlPath, "/")

	if urlPath == "" {
		return nil, fmt.Errorf("empty URL path")
	}

	// Split path into segments
	segments := strings.Split(urlPath, "/")

	// files.pythonhosted.org paths start with "packages"
	// Format: packages/{hash_prefix}/{filename}
	// The hash prefix can be variable length (typically 2-3 directory levels)
	if len(segments) < 2 {
		return nil, fmt.Errorf("invalid PyPI files URL: not enough segments")
	}

	// The filename is always the last segment
	filename := segments[len(segments)-1]

	// Check if it's a packages download path
	if segments[0] != "packages" {
		return nil, fmt.Errorf("invalid PyPI files URL: expected 'packages' prefix, got %s", segments[0])
	}

	return parseFilename(filename)
}

// pypiOrgParser parses URLs from pypi.org (Simple API and JSON API)
type pypiOrgParser struct{}

// Ensure pypiOrgParser implements RegistryURLParser interface
var _ registryURLParser = pypiOrgParser{}

// ParseURL parses pypi.org URL paths
// URL patterns:
// - /simple/{package}/ (Simple API - package index)
// - /simple/{package}/{filename} (Simple API - file redirect, rare)
// - /pypi/{package}/json (JSON API - package metadata)
// - /pypi/{package}/{version}/json (JSON API - version metadata)
func (p pypiOrgParser) ParseURL(urlPath string) (packageInfo, error) {
	// Remove leading and trailing slashes
	urlPath = strings.Trim(urlPath, "/")

	if urlPath == "" {
		return nil, fmt.Errorf("empty URL path")
	}

	// Split path into segments
	segments := strings.Split(urlPath, "/")

	if len(segments) < 2 {
		return nil, fmt.Errorf("invalid pypi.org URL: not enough segments")
	}

	switch segments[0] {
	case "simple":
		// Simple API: /simple/{package}/ or /simple/{package}/{filename}
		return parseSimpleAPIURL(segments[1:])
	case "pypi":
		// JSON API: /pypi/{package}/json or /pypi/{package}/{version}/json
		return parseJSONAPIURL(segments[1:])
	default:
		return nil, fmt.Errorf("unknown pypi.org path prefix: %s", segments[0])
	}
}

// parseSimpleAPIURL parses Simple API URL paths
func parseSimpleAPIURL(segments []string) (*pypiPackageInfo, error) {
	if len(segments) == 0 {
		return nil, fmt.Errorf("invalid Simple API URL: missing package name")
	}

	packageName := segments[0]

	// Simple API index request: /simple/{package}/
	if len(segments) == 1 {
		return &pypiPackageInfo{
			name:       denormalizePyPIPackageName(packageName),
			isDownload: false,
		}, nil
	}

	// Simple API might include filename (for redirects): /simple/{package}/{filename}
	if len(segments) == 2 {
		filename := segments[1]
		info, err := parseFilename(filename)
		if err != nil {
			// If we can't parse the filename, treat it as a non-download request
			return &pypiPackageInfo{
				name:       denormalizePyPIPackageName(packageName),
				isDownload: false,
			}, nil
		}
		return info, nil
	}

	return nil, fmt.Errorf("invalid Simple API URL format: too many segments")
}

// parseJSONAPIURL parses JSON API URL paths
func parseJSONAPIURL(segments []string) (*pypiPackageInfo, error) {
	if len(segments) == 0 {
		return nil, fmt.Errorf("invalid JSON API URL: missing package name")
	}

	packageName := segments[0]

	// /pypi/{package}/json - package metadata (no specific version)
	if len(segments) == 2 && segments[1] == "json" {
		return &pypiPackageInfo{
			name:       denormalizePyPIPackageName(packageName),
			isDownload: false,
		}, nil
	}

	// /pypi/{package}/{version}/json - version metadata
	if len(segments) == 3 && segments[2] == "json" {
		return &pypiPackageInfo{
			name:       denormalizePyPIPackageName(packageName),
			version:    segments[1],
			isDownload: false,
		}, nil
	}

	return nil, fmt.Errorf("invalid JSON API URL format")
}

// parseFilename extracts package name and version from a PyPI distribution filename
func parseFilename(filename string) (*pypiPackageInfo, error) {
	// Try to parse as wheel first
	if strings.HasSuffix(filename, ".whl") {
		return parseWheelFilename(filename)
	}

	// Try to parse as sdist (tar.gz or zip)
	if strings.HasSuffix(filename, ".tar.gz") || strings.HasSuffix(filename, ".zip") {
		return parseSdistFilename(filename)
	}

	// Check for other archive formats that PyPI might serve
	if strings.HasSuffix(filename, ".tar.bz2") || strings.HasSuffix(filename, ".tgz") {
		return parseSdistFilename(filename)
	}

	return nil, fmt.Errorf("unsupported file type: %s", filename)
}

// parseWheelFilename parses a wheel filename to extract package info
// Wheel filename format: {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl
// Examples:
// - requests-2.28.0-py3-none-any.whl
// - numpy-1.24.0-cp311-cp311-linux_x86_64.whl
// - package_name-1.0.0-1-py3-none-any.whl (with build tag)
func parseWheelFilename(filename string) (*pypiPackageInfo, error) {
	// Remove .whl extension
	basename := strings.TrimSuffix(filename, ".whl")

	// Split by '-' to get components
	// Minimum: name-version-python-abi-platform (5 parts)
	// With build tag: name-version-build-python-abi-platform (6 parts)
	parts := strings.Split(basename, "-")

	if len(parts) < 5 {
		return nil, fmt.Errorf("invalid wheel filename: not enough components in %s", filename)
	}

	// The last 3 parts are always: python_tag, abi_tag, platform_tag
	// Before that is either: name, version OR name, version, build_tag
	// We need to find where the version is

	// Work backwards: last 3 are tags
	// If 6+ parts, could have build tag
	// If 5 parts, no build tag

	var name, version string

	if len(parts) == 5 {
		// name-version-python-abi-platform
		name = parts[0]
		version = parts[1]
	} else if len(parts) == 6 {
		// Could be:
		// - name-version-build-python-abi-platform (6 parts, with build tag)
		// - name_with_underscore-version-python-abi-platform (can't be this, underscores in names are normalized)
		// Build tags are numeric (PEP 427)
		if isBuildTag(parts[2]) {
			name = parts[0]
			version = parts[1]
		} else {
			// The name might contain a hyphen that wasn't normalized
			// This shouldn't happen with properly normalized names, but handle it
			name = parts[0] + "_" + parts[1]
			version = parts[2]
		}
	} else {
		// More than 6 parts - name contains hyphens or there's a build tag
		// Try to find version by looking for semver-like pattern
		name, version = extractNameVersionFromParts(parts[:len(parts)-3])
		if name == "" || version == "" {
			return nil, fmt.Errorf("could not parse wheel filename: %s", filename)
		}
	}

	return &pypiPackageInfo{
		name:       denormalizePyPIPackageName(name),
		version:    version,
		isDownload: true,
		fileType:   "wheel",
	}, nil
}

// isBuildTag checks if a string looks like a wheel build tag (numeric)
func isBuildTag(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseSdistFilename parses a source distribution filename to extract package info
// Sdist filename format: {name}-{version}.tar.gz or {name}-{version}.zip
// Examples:
// - requests-2.28.0.tar.gz
// - Flask-RESTful-0.3.10.tar.gz (note: hyphens in name)
func parseSdistFilename(filename string) (*pypiPackageInfo, error) {
	// Remove extension
	basename := filename
	for _, ext := range []string{".tar.gz", ".tar.bz2", ".tgz", ".zip"} {
		if strings.HasSuffix(basename, ext) {
			basename = strings.TrimSuffix(basename, ext)
			break
		}
	}

	// Find the version by looking for the last hyphen followed by a version-like string
	// This is tricky because package names can contain hyphens
	name, version := extractNameVersionFromSdist(basename)
	if name == "" || version == "" {
		return nil, fmt.Errorf("could not parse sdist filename: %s", filename)
	}

	return &pypiPackageInfo{
		name:       denormalizePyPIPackageName(name),
		version:    version,
		isDownload: true,
		fileType:   "sdist",
	}, nil
}

// extractNameVersionFromSdist extracts name and version from a sdist basename
// The challenge is that package names can contain hyphens, so we need to find
// where the name ends and the version begins
func extractNameVersionFromSdist(basename string) (string, string) {
	// Version pattern: starts with a digit, may contain digits, dots, and pre-release suffixes
	versionPattern := regexp.MustCompile(`^\d+(\.\d+)*([._-]?(a|alpha|b|beta|c|rc|pre|post|dev|final)\.?\d*)*(\+[a-zA-Z0-9._-]+)?$`)

	// Split by hyphen and try to find where version starts
	parts := strings.Split(basename, "-")

	// Try from the end, looking for version-like parts
	for i := len(parts) - 1; i > 0; i-- {
		potentialVersion := strings.Join(parts[i:], "-")
		// Check if this could be a version
		if versionPattern.MatchString(potentialVersion) {
			name := strings.Join(parts[:i], "-")
			return name, potentialVersion
		}

		// Also try just the single part as version
		if versionPattern.MatchString(parts[i]) {
			name := strings.Join(parts[:i], "-")
			return name, parts[i]
		}
	}

	return "", ""
}

// extractNameVersionFromParts extracts name and version from wheel filename parts
// (excluding the python-abi-platform tags)
func extractNameVersionFromParts(parts []string) (string, string) {
	if len(parts) < 2 {
		return "", ""
	}

	// Version pattern for wheels
	versionPattern := regexp.MustCompile(`^\d+(\.\d+)*([._]?(a|alpha|b|beta|c|rc|pre|post|dev|final)\d*)*(\+[a-zA-Z0-9._]+)?$`)

	// Try from the end, looking for version-like parts
	for i := len(parts) - 1; i > 0; i-- {
		if versionPattern.MatchString(parts[i]) {
			// Check if next part is a build tag (numeric only)
			if i+1 < len(parts) && isBuildTag(parts[i+1]) {
				// This is the version, parts[i+1] is build tag
				name := strings.Join(parts[:i], "_")
				return name, parts[i]
			}
			name := strings.Join(parts[:i], "_")
			return name, parts[i]
		}
	}

	// Fallback: assume first part is name, second is version
	return parts[0], parts[1]
}

// denormalizePyPIPackageName converts a normalized package name back to a more canonical form
// PyPI normalizes names by replacing [-_.] with - and lowercasing
// We can't fully reverse this, but we keep the normalized form which works for lookups
func denormalizePyPIPackageName(name string) string {
	// Convert underscores to hyphens (common PyPI convention)
	// Keep lowercase as that's the normalized form
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}
