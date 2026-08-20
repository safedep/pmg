package interceptors

import (
	"fmt"
	"net/url"
	"sort"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/registryurl"
)

// CustomRegistriesByEcosystem is the compiled, request-time form of every
// user-configured registry endpoint. Compiled once per flow (flows and the
// proxy server call CompileCustomRegistries) and shared through
// InterceptorContext.CustomRegistries.
type CustomRegistriesByEcosystem map[string][]*registryConfig

// Origins renders every compiled endpoint as a canonical host:effectivePort
// pair for audit suppression.
func (c CustomRegistriesByEcosystem) Origins() []string {
	set := make(map[string]struct{})
	for _, configs := range c {
		for _, config := range configs {
			set[registryOrigin(config.Host, config.effectivePort)] = struct{}{}
		}
	}
	origins := make([]string, 0, len(set))
	for origin := range set {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	return origins
}

// CompileCustomRegistries compiles user-configured endpoints into
// request-time registryConfigs, validating first. Called once per flow; the
// result is shared with every consumer via InterceptorContext.
func CompileCustomRegistries(registries []config.ProxyRegistryConfig) (CustomRegistriesByEcosystem, error) {
	if err := config.ValidateProxyRegistries(registries); err != nil {
		return nil, fmt.Errorf("invalid custom proxy registries: %w", err)
	}

	compiled := make(CustomRegistriesByEcosystem)
	for _, registry := range registries {
		for _, endpoint := range registry.Endpoints {
			u, err := registryurl.Normalize(endpoint.URL)
			if err != nil {
				return nil, fmt.Errorf("invalid custom proxy registry %q endpoint: %w", registry.Name, err)
			}
			if covered := builtInRegistryCoverage(registry.Ecosystem).GetConfigForHostname(u.Hostname()); covered != nil {
				return nil, fmt.Errorf("invalid custom %s registry %q endpoint: host %q is covered by the built-in %s registries",
					registry.Ecosystem, registry.Name, u.Hostname(), registry.Ecosystem)
			}

			config := &registryConfig{
				Name:                 registry.Name,
				Host:                 u.Hostname(),
				Scheme:               u.Scheme,
				Port:                 u.Port(),
				BasePath:             u.EscapedPath(),
				MatchSubdomains:      false,
				SupportedForAnalysis: true,
				Parser:               customRegistryParser(registry.Ecosystem, u),
			}
			normalizeRegistryConfig(config)
			compiled[registry.Ecosystem] = append(compiled[registry.Ecosystem], config)
			if u.Scheme == "http" {
				log.Warnf("Custom registry endpoint %q uses plain HTTP; traffic is inspectable but not encrypted", u.String())
			}
		}
	}
	return compiled, nil
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
// here keeps runtime matching free of ambiguity rules.
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
