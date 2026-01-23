package interceptors

import "strings"

// npmRegistryConfig defines configuration for npm registry endpoints
type npmRegistryConfig struct {
	// Endpoint hostname
	Endpoint string

	// Whether this registry is supported for malware analysis
	SupportedForAnalysis bool

	// Parser for the registry
	RegistryParser RegistryURLParser
}

// GetNpmRegistryEndpoints returns a list of all supported npm registry endpoints
func GetNpmRegistryEndpoints() []string {
	endpoints := make([]string, 0, len(npmRegistryDomains))
	for endpoint := range npmRegistryDomains {
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

// GetNpmRegistryConfigForHostname returns the configuration for a hostname (with subdomain matching)
func GetNpmRegistryConfigForHostname(hostname string) *npmRegistryConfig {
	// Check exact match first
	if config, exists := npmRegistryDomains[hostname]; exists {
		return config
	}

	// Check subdomain match: hostname could be "cdn.registry.npmjs.org" matching "registry.npmjs.org"
	for endpoint, config := range npmRegistryDomains {
		if strings.HasSuffix(hostname, "."+endpoint) {
			return config
		}
	}

	return nil
}
