package interceptors

import "strings"

// packageInfo represents parsed package information from a registry URL.
// All ecosystem-specific package info types must implement this interface.
type packageInfo interface {
	// GetName returns the package name
	GetName() string

	// GetVersion returns the package version (may be empty for metadata requests)
	GetVersion() string

	// IsFileDownload returns true if this is a file download request (tarball, wheel, etc.)
	// Returns false for metadata requests (package index, version info, etc.)
	IsFileDownload() bool
}

// registryURLParser parses registry-specific URLs to extract package information.
// Each registry (npm, pypi, etc.) implements this interface with its own URL parsing logic.
type registryURLParser interface {
	// ParseURL parses a URL path and returns package information.
	// Returns an error if the URL cannot be parsed.
	ParseURL(urlPath string) (packageInfo, error)
}

// registryConfig defines configuration for a package registry endpoint.
// This is the common configuration structure used by all ecosystem interceptors.
type registryConfig struct {
	// Host is the hostname of the registry
	Host string

	// SupportedForAnalysis indicates whether this registry supports malware analysis.
	// Some registries (like private registries or test instances) may not support analysis.
	SupportedForAnalysis bool

	// Parser is the URL parser for this registry
	Parser registryURLParser
}

// registryConfigMap is a map of hostname to registry configuration
type registryConfigMap map[string]*registryConfig

// GetConfigForHostname returns the configuration for a hostname with subdomain matching support.
// It first checks for an exact match, then checks if the hostname is a subdomain of any configured registry.
func (m registryConfigMap) GetConfigForHostname(hostname string) *registryConfig {
	// Check exact match first
	if config, exists := m[hostname]; exists {
		return config
	}

	// Check subdomain match: hostname could be "cdn.registry.example.org" matching "registry.example.org".
	// Defensive: Since Go map iteration order is non-deterministic, if multiple endpoints could match
	// (e.g., both "example.org" and "registry.example.org"), we select the longest (most specific) one
	// to ensure consistent behavior. In practice, our configured endpoints don't overlap.
	var bestConfig *registryConfig
	bestLen := 0
	for endpoint, config := range m {
		if strings.HasSuffix(hostname, "."+endpoint) {
			if len(endpoint) > bestLen {
				bestLen = len(endpoint)
				bestConfig = config
			}
		}
	}

	return bestConfig
}

// ContainsHostname checks if the hostname matches any configured registry (exact or subdomain match)
func (m registryConfigMap) ContainsHostname(hostname string) bool {
	return m.GetConfigForHostname(hostname) != nil
}
