package interceptors

import "strings"

// npmRegistryConfig defines configuration for npm registry endpoints
type npmRegistryConfig struct {
	// Hostname
	Host string

	// Whether this registry is supported for malware analysis
	SupportedForAnalysis bool

	// Parser for the registry
	RegistryParser npmRegistryURLParser
}

// getNpmRegistryConfigForHostname returns the configuration for a hostname (with subdomain matching)
func getNpmRegistryConfigForHostname(hostname string) *npmRegistryConfig {
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
