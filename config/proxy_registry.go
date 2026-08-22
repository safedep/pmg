package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"

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

// normalizedEndpoint splits a normalized endpoint URL into its origin and
// base path so endpoint nesting can be checked across all registries.
type normalizedEndpoint struct {
	rawURL string
	origin string
	path   string
}

func splitEndpoint(rawURL string, u *url.URL) normalizedEndpoint {
	return normalizedEndpoint{
		rawURL: rawURL,
		origin: u.Scheme + "://" + u.Host,
		path:   u.EscapedPath(),
	}
}

func ValidateProxyRegistries(registries []ProxyRegistryConfig) error {
	names := make(map[string]struct{}, len(registries))
	endpoints := make(map[string]string)
	var byOrigin []normalizedEndpoint

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
			normalized, err := registryurl.Normalize(endpoint.URL)
			if err != nil {
				return fmt.Errorf("proxy registry %q endpoint %d: %w", name, endpointIndex, err)
			}
			if owner, exists := endpoints[normalized.String()]; exists {
				return fmt.Errorf("proxy registry endpoint %q is already assigned to %q", normalized, owner)
			}
			endpoints[normalized.String()] = name

			if err := validateEndpointHost(normalized.Hostname()); err != nil {
				return fmt.Errorf("proxy registry %q endpoint %d: %w", name, endpointIndex, err)
			}

			split := splitEndpoint(endpoint.URL, normalized)
			// Nested base paths on one origin are ambiguous regardless of
			// ecosystem: in daemon mode both interceptors would handle the
			// nested requests, and even single-ecosystem nesting forces an
			// arbitration rule the config should state explicitly instead.
			for _, existing := range byOrigin {
				if existing.origin == split.origin && endpointPathsNest(existing.path, split.path) {
					return fmt.Errorf("proxy registry %q endpoint %d (%q) overlaps %q: endpoint base paths on the same origin must not nest",
						name, endpointIndex, endpoint.URL, existing.rawURL)
				}
			}
			byOrigin = append(byOrigin, split)
		}
	}

	return nil
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
// the same origin.
func endpointPathsNest(a, b string) bool {
	if a == "" || b == "" || a == b {
		return true
	}
	return strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
