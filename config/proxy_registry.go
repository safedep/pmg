package config

import (
	"fmt"
	"net/url"
	"strings"
)

type ProxyRegistryConfig struct {
	Name      string                        `mapstructure:"name"`
	Ecosystem string                        `mapstructure:"ecosystem"`
	Endpoints []ProxyRegistryEndpointConfig `mapstructure:"endpoints"`
}

type ProxyRegistryEndpointConfig struct {
	URL string `mapstructure:"url"`
}

func ValidateProxyRegistries(registries []ProxyRegistryConfig) error {
	names := make(map[string]struct{}, len(registries))
	endpoints := make(map[string]string)

	for registryIndex, registry := range registries {
		name := strings.TrimSpace(registry.Name)
		if name == "" {
			return fmt.Errorf("proxy.registries[%d].name is required", registryIndex)
		}
		if _, exists := names[name]; exists {
			return fmt.Errorf("duplicate proxy registry name %q", name)
		}
		names[name] = struct{}{}

		if registry.Ecosystem != "npm" && registry.Ecosystem != "pypi" {
			return fmt.Errorf("proxy registry %q has unsupported ecosystem %q", name, registry.Ecosystem)
		}
		if len(registry.Endpoints) == 0 {
			return fmt.Errorf("proxy registry %q must define at least one endpoint", name)
		}

		for endpointIndex, endpoint := range registry.Endpoints {
			normalized, err := normalizeProxyRegistryURL(endpoint.URL)
			if err != nil {
				return fmt.Errorf("proxy registry %q endpoint %d: %w", name, endpointIndex, err)
			}
			if owner, exists := endpoints[normalized]; exists {
				return fmt.Errorf("proxy registry endpoint %q is already assigned to %q", normalized, owner)
			}
			endpoints[normalized] = name
		}
	}

	return nil
}

func normalizeProxyRegistryURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if !parsed.IsAbs() {
		return "", fmt.Errorf("URL must be absolute")
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("URL scheme must be http or https")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", fmt.Errorf("URL host is required")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("URL must not include credentials")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return "", fmt.Errorf("URL must not include a query")
	}
	if parsed.Fragment != "" || strings.Contains(rawURL, "#") {
		return "", fmt.Errorf("URL must not include a fragment")
	}

	hostname := strings.ToLower(parsed.Hostname())
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}

	port := parsed.Port()
	if port != "" && !(scheme == "http" && port == "80") && !(scheme == "https" && port == "443") {
		host += ":" + port
	}

	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	return scheme + "://" + host + path, nil
}
