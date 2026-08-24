package config

import (
	"fmt"
	"net"
	"strings"
	"unicode"

	"github.com/safedep/pmg/internal/registryurl"
)

// ProxyRegistryEcosystem is the canonical set of ecosystems proxy.registries
// accepts. The interceptor layer keys its ecosystem table on this type, so a
// new ecosystem is added here first.
type ProxyRegistryEcosystem string

const (
	ProxyRegistryEcosystemNpm  ProxyRegistryEcosystem = "npm"
	ProxyRegistryEcosystemPypi ProxyRegistryEcosystem = "pypi"
)

func ProxyRegistryEcosystems() []ProxyRegistryEcosystem {
	return []ProxyRegistryEcosystem{ProxyRegistryEcosystemNpm, ProxyRegistryEcosystemPypi}
}

func (e ProxyRegistryEcosystem) Valid() bool {
	for _, known := range ProxyRegistryEcosystems() {
		if e == known {
			return true
		}
	}
	return false
}

type ProxyRegistryConfig struct {
	Name      string                        `mapstructure:"name"`
	Ecosystem ProxyRegistryEcosystem        `mapstructure:"ecosystem"`
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

// NormalizedRegistryEndpoint is one custom registry endpoint after
// validation and URL normalization. The registry catalog consumes this model
// directly, so config loading and catalog construction share one
// normalization pass.
type NormalizedRegistryEndpoint struct {
	RegistryName string
	Ecosystem    ProxyRegistryEcosystem
	URL          string
	Scheme       string
	// Host is the lowercase hostname without brackets or port.
	Host string
	// Port is the effective port: the configured port, or the scheme default.
	Port string
	// BasePath is the normalized escaped base path with no trailing slash.
	BasePath string
}

func (e NormalizedRegistryEndpoint) origin() string {
	return e.Scheme + "://" + e.Host + ":" + e.Port
}

func ValidateProxyRegistries(registries []ProxyRegistryConfig) error {
	_, err := NormalizeProxyRegistries(registries)
	return err
}

// NormalizeProxyRegistries validates proxy.registries and returns the
// normalized endpoint model. It fails on the first invalid entry.
func NormalizeProxyRegistries(registries []ProxyRegistryConfig) ([]NormalizedRegistryEndpoint, error) {
	names := make(map[string]struct{}, len(registries))
	owners := make(map[string]string)
	var normalized []NormalizedRegistryEndpoint

	for registryIndex, registry := range registries {
		name := strings.TrimSpace(registry.Name)
		if name == "" {
			return nil, fmt.Errorf("proxy.registries[%d].name is required", registryIndex)
		}
		if name != registry.Name {
			return nil, fmt.Errorf("proxy.registries[%d].name must not have leading or trailing whitespace", registryIndex)
		}
		if _, exists := names[name]; exists {
			return nil, fmt.Errorf("duplicate proxy registry name %q", name)
		}
		names[name] = struct{}{}

		if !registry.Ecosystem.Valid() {
			return nil, fmt.Errorf("proxy registry %q has unsupported ecosystem %q", name, registry.Ecosystem)
		}
		if len(registry.Endpoints) == 0 {
			return nil, fmt.Errorf("proxy registry %q must define at least one endpoint", name)
		}

		for endpointIndex, endpoint := range registry.Endpoints {
			u, err := registryurl.Normalize(endpoint.URL)
			if err != nil {
				return nil, fmt.Errorf("proxy registry %q endpoint %d: %w", name, endpointIndex, err)
			}
			if owner, exists := owners[u.String()]; exists {
				return nil, fmt.Errorf("proxy registry endpoint %q is already assigned to %q", u, owner)
			}
			owners[u.String()] = name

			if err := validateEndpointHost(u.Hostname()); err != nil {
				return nil, fmt.Errorf("proxy registry %q endpoint %d: %w", name, endpointIndex, err)
			}

			port, valid := registryurl.EffectivePort(u.Scheme, u.Port())
			if !valid {
				return nil, fmt.Errorf("proxy registry %q endpoint %d: URL port must be between 1 and 65535", name, endpointIndex)
			}

			entry := NormalizedRegistryEndpoint{
				RegistryName: name,
				Ecosystem:    registry.Ecosystem,
				URL:          u.String(),
				Scheme:       u.Scheme,
				Host:         u.Hostname(),
				Port:         port,
				BasePath:     u.EscapedPath(),
			}

			// Nested base paths on one origin are ambiguous regardless of
			// ecosystem: in daemon mode both interceptors would handle the
			// nested requests, and even single-ecosystem nesting forces an
			// arbitration rule the config should state explicitly instead.
			for _, existing := range normalized {
				if existing.origin() == entry.origin() && endpointPathsNest(existing.BasePath, entry.BasePath) {
					return nil, fmt.Errorf("proxy registry %q endpoint %d (%q) overlaps %q: endpoint base paths on the same origin must not nest",
						name, endpointIndex, endpoint.URL, existing.URL)
				}
			}
			normalized = append(normalized, entry)
		}
	}

	return normalized, nil
}

// validateEndpointHost rejects endpoint hosts PMG can never analyze:
// loopback hosts (proxied runs export NO_PROXY=localhost,127.0.0.1,::1, so
// they bypass the proxy entirely) and non-ASCII hostnames (package managers
// punycode before connecting, so a Unicode entry never matches the wire).
// The hostname arrives already normalized by registryurl.Normalize.
func validateEndpointHost(hostname string) error {
	if ip := net.ParseIP(hostname); ip != nil {
		if ip.IsLoopback() {
			return fmt.Errorf("host %q is a loopback address; proxied runs exclude loopback hosts via NO_PROXY, so PMG cannot analyze them", hostname)
		}
		if ip.IsUnspecified() {
			return fmt.Errorf("host %q is an unspecified address and cannot identify a registry", hostname)
		}
	}
	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		return fmt.Errorf("host %q is loopback-only; proxied runs exclude localhost via NO_PROXY, so PMG cannot analyze it", hostname)
	}
	for _, r := range hostname {
		if r > unicode.MaxASCII {
			return fmt.Errorf("host %q is not ASCII; package managers punycode hostnames before connecting, so use the punycode (xn--) form", hostname)
		}
	}
	return nil
}

// endpointPathsNest reports whether one base path is a segment-prefix of the
// other (either direction). An empty base path nests with every other path on
// the same origin. Equal paths nest too, though the duplicate-endpoint check
// reports those before this rule runs.
func endpointPathsNest(a, b string) bool {
	if a == "" || b == "" || a == b {
		return true
	}
	return strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
