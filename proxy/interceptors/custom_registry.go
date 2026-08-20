package interceptors

import (
	"fmt"
	"net/url"
	"sort"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/registryurl"
)

// customRegistryConfigs compiles the user-configured endpoints of one
// ecosystem into request-time registryConfigs. Called once per interceptor
// construction; compile errors surface there directly.
func customRegistryConfigs(registries []config.ProxyRegistryConfig, ecosystem string) ([]*registryConfig, error) {
	if err := config.ValidateProxyRegistries(registries); err != nil {
		return nil, fmt.Errorf("invalid custom proxy registries: %w", err)
	}

	var configs []*registryConfig
	for _, registry := range registries {
		if registry.Ecosystem != ecosystem {
			continue
		}
		for _, endpoint := range registry.Endpoints {
			u, err := normalizedRegistryEndpoint(endpoint.URL)
			if err != nil {
				return nil, fmt.Errorf("invalid custom proxy registry %q endpoint: %w", registry.Name, err)
			}
			if covered := builtInRegistryCoverage(ecosystem).GetConfigForHostname(u.Hostname()); covered != nil {
				return nil, fmt.Errorf("invalid custom %s registry %q endpoint: host %q is covered by the built-in %s registries",
					ecosystem, registry.Name, u.Hostname(), ecosystem)
			}

			configs = append(configs, &registryConfig{
				Name:                 registry.Name,
				Host:                 u.Hostname(),
				Scheme:               u.Scheme,
				Port:                 u.Port(),
				BasePath:             u.EscapedPath(),
				MatchSubdomains:      false,
				SupportedForAnalysis: true,
				Parser:               customRegistryParser(ecosystem, u),
			})
			if u.Scheme == "http" {
				log.Warnf("Custom registry endpoint %q uses plain HTTP; traffic is inspectable but not encrypted", u.String())
			}
		}
	}
	return configs, nil
}

// customRegistryOrigins renders every configured endpoint as a canonical
// host:effectivePort pair for audit suppression. Built best-effort: the
// ecosystem interceptors are constructed first and their compile error
// surfaces there, so anything invalid never reaches the audit logger.
func customRegistryOrigins(registries []config.ProxyRegistryConfig) []string {
	set := make(map[string]struct{})
	for _, registry := range registries {
		for _, endpoint := range registry.Endpoints {
			u, err := normalizedRegistryEndpoint(endpoint.URL)
			if err != nil {
				continue
			}
			set[registryOrigin(u.Hostname(), u.Scheme, u.Port())] = struct{}{}
		}
	}
	origins := make([]string, 0, len(set))
	for origin := range set {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	return origins
}

// customRegistryParser picks the URL parser for an endpoint. pypi's parser
// depends on this endpoint's own base path (whether it ends in "/simple"),
// so it is built per endpoint, not once per registry.
func customRegistryParser(ecosystem string, u *url.URL) registryURLParser {
	if ecosystem == "pypi" {
		return pypiCustomParser{baseEndsInSimple: pypiBaseEndsInSimple(u.EscapedPath())}
	}
	return npmParser{}
}

// builtInRegistryCoverage returns the built-in domain map for an ecosystem,
// used to reject custom endpoints whose host is already covered by a built-in
// registry (exact host or subdomain of a built-in host). Rejecting overlap
// here keeps runtime matching free of resolution order.
func builtInRegistryCoverage(ecosystem string) registryConfigMap {
	switch ecosystem {
	case "npm":
		return npmRegistryDomains
	case "pypi":
		return pypiRegistryDomains
	default:
		return nil
	}
}

func normalizedRegistryEndpoint(rawURL string) (*url.URL, error) {
	normalized, err := registryurl.Normalize(rawURL)
	if err != nil {
		return nil, err
	}
	return url.Parse(normalized)
}
