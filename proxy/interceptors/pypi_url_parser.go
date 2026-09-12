package interceptors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/safedep/pmg/internal/pypi"
)

var (
	pypiEggFilename = regexp.MustCompile(`^([^-]+)-([^-]+)(?:-(?:py[0-9.]+|cp[0-9]+)(?:-[a-zA-Z0-9_.-]+)?)?\.egg$`)
	pypiExeFilename = regexp.MustCompile(`^(.+)-([^-]+)\.(?:win32|win-amd64)(?:-py[0-9.]+)?\.exe$`)
)

// pypiPackageInfo represents parsed package information from a PyPI registry URL
type pypiPackageInfo struct {
	name       string
	version    string
	isDownload bool // True if this is a file download (sdist or wheel)

	// isSimpleAPI is true when parsed from a Simple API (PEP 503/691) path,
	// false for the legacy JSON API request. A custom registry can reshape
	// the absolute path with an arbitrary prefix, so callers use this
	// instead of matching on the path.
	isSimpleAPI bool
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

// IsSimpleAPI reports whether this was parsed from a Simple API path rather
// than the legacy JSON API. Meaningful only when IsFileDownload is false.
func (p *pypiPackageInfo) IsSimpleAPI() bool {
	return p.isSimpleAPI
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
	if len(segments) == 0 || (len(segments) == 1 && segments[0] == "index.html") {
		return &pypiPackageInfo{}, nil
	}

	packageName := segments[0]

	// Simple API index request: /simple/{package}/
	if len(segments) == 1 || (len(segments) == 2 && segments[1] == "index.html") {
		return &pypiPackageInfo{
			name:        denormalizePyPIPackageName(packageName),
			isDownload:  false,
			isSimpleAPI: true,
		}, nil
	}

	// Simple API might include filename (for redirects): /simple/{package}/{filename}
	if len(segments) == 2 {
		return parseFilename(segments[1])
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
	isMetadata := strings.HasSuffix(filename, ".metadata")
	info, err := parseDistributionFilename(strings.TrimSuffix(filename, ".metadata"))
	if err != nil {
		return nil, err
	}
	if isMetadata {
		info.isDownload = false
	}
	return info, nil
}

func parseDistributionFilename(filename string) (*pypiPackageInfo, error) {
	for _, legacy := range []*regexp.Regexp{pypiEggFilename, pypiExeFilename} {
		if matches := legacy.FindStringSubmatch(filename); matches != nil {
			version, valid := pypi.NormalizeVersion(matches[2])
			if !valid {
				return nil, fmt.Errorf("artifact filename %q has an invalid version", filename)
			}
			return &pypiPackageInfo{name: denormalizePyPIPackageName(matches[1]), version: version, isDownload: true}, nil
		}
	}
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
	basename := strings.TrimSuffix(filename, ".whl")
	parts := strings.Split(basename, "-")

	if len(parts) != 5 && len(parts) != 6 {
		return nil, fmt.Errorf("wheel filename %q must have five or six components", filename)
	}
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("wheel filename %q has an empty component", filename)
		}
	}
	name := parts[0]
	version, valid := pypi.NormalizeVersion(parts[1])
	if len(parts) == 6 && !valid {
		// Older indexes can serve wheel names with an unescaped hyphen.
		name = strings.Join(parts[:2], "-")
		version, valid = pypi.NormalizeVersion(parts[2])
	} else if len(parts) == 6 && !isBuildTag(parts[2]) {
		return nil, fmt.Errorf("wheel filename %q has an invalid build tag", filename)
	}
	if name == "" || !valid {
		return nil, fmt.Errorf("wheel filename %q has an invalid package name or version", filename)
	}

	return &pypiPackageInfo{
		name:       denormalizePyPIPackageName(name),
		version:    version,
		isDownload: true,
	}, nil
}

func isBuildTag(s string) bool {
	return len(s) > 0 && s[0] >= '0' && s[0] <= '9'
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
	}, nil
}

// extractNameVersionFromSdist extracts name and version from a sdist basename
// The challenge is that package names can contain hyphens, so we need to find
// where the name ends and the version begins
func extractNameVersionFromSdist(basename string) (string, string) {
	// Split by hyphen and try to find where version starts
	parts := strings.Split(basename, "-")

	// Try from the end, looking for version-like parts
	for i := len(parts) - 1; i > 0; i-- {
		potentialVersion := strings.Join(parts[i:], "-")
		// Check if this could be a version
		if version, valid := pypi.NormalizeVersion(potentialVersion); valid {
			name := strings.Join(parts[:i], "-")
			return name, version
		}
	}

	return "", ""
}

// denormalizePyPIPackageName converts a normalized package name back to a more canonical form
// PyPI normalizes names by replacing [-_.] with - and lowercasing
// We can't fully reverse this, but we keep the normalized form which works for lookups
func denormalizePyPIPackageName(name string) string {
	// Convert underscores to hyphens (common PyPI convention)
	// Keep lowercase as that's the normalized form
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}
