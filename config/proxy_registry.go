package config

import (
	"fmt"
	"strings"

	"github.com/safedep/pmg/internal/registryurl"
)

type ProxyRegistryConfig struct {
	Name      string                        `mapstructure:"name"`
	Ecosystem string                        `mapstructure:"ecosystem"`
	Endpoints []ProxyRegistryEndpointConfig `mapstructure:"endpoints"`
}

type ProxyRegistryEndpointConfig struct {
	URL string `mapstructure:"url"`
}

// ProxyRegistriesError wraps a proxy.registries validation failure so
// callers can detect it via errors.As and fail closed instead of falling
// back to defaults, which would silently drop the custom-registry
// protection configured.
type ProxyRegistriesError struct {
	err error
}

func (e *ProxyRegistriesError) Error() string {
	return fmt.Sprintf("invalid proxy registries: %v", e.err)
}

func (e *ProxyRegistriesError) Unwrap() error {
	return e.err
}

func ValidateProxyRegistries(registries []ProxyRegistryConfig) error {
	names := make(map[string]struct{}, len(registries))
	endpoints := make(map[string]string)

	for registryIndex, registry := range registries {
		name := strings.TrimSpace(registry.Name)
		if name == "" {
			return fmt.Errorf("proxy.registries[%d].name is required", registryIndex)
		}
		if name != registry.Name {
			return fmt.Errorf("proxy.registries[%d].name must not have leading or trailing whitespace", registryIndex)
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
	return registryurl.Normalize(rawURL)
}
