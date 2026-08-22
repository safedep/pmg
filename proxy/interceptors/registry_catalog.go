package interceptors

import (
	"fmt"
	"net/http"
	"net/url"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/registryurl"
	"github.com/safedep/pmg/proxy"
)

type RegistryCatalog struct {
	byEcosystem map[packagev1.Ecosystem]registrySet
}

func NewRegistryCatalog(registries []config.ProxyRegistryConfig) (*RegistryCatalog, error) {
	// Keep this boundary self-validating because callers can construct a
	// catalog directly without going through the global config loader.
	if err := config.ValidateProxyRegistries(registries); err != nil {
		return nil, fmt.Errorf("invalid custom proxy registries: %w", err)
	}

	catalog := newBuiltInRegistryCatalog()

	for _, registry := range registries {
		ecosystem := registryEcosystem(registry.Ecosystem)
		for _, configured := range registry.Endpoints {
			u, err := registryurl.Normalize(configured.URL)
			if err != nil {
				return nil, fmt.Errorf("invalid custom proxy registry %q endpoint: %w", registry.Name, err)
			}
			if endpoint := catalog.builtInForHostname(u.Hostname()); endpoint != nil {
				return nil, fmt.Errorf("invalid custom %s registry %q endpoint: host %q is covered by the built-in npm/PyPI registries",
					registry.Ecosystem, registry.Name, u.Hostname())
			}

			port, valid := registryurl.EffectivePort(u.Scheme, u.Port())
			if !valid {
				return nil, fmt.Errorf("invalid custom proxy registry %q endpoint port", registry.Name)
			}
			endpoint := registryEndpoint{
				Name:     registry.Name,
				Source:   registrySourceCustom,
				Scope:    registryScopeOrigin,
				Scheme:   u.Scheme,
				Host:     u.Hostname(),
				Port:     port,
				BasePath: registryurl.NormalizeBasePath(u.EscapedPath()),
				Analyze:  true,
				Parser:   customRegistryParser(ecosystem, u),
			}
			set := catalog.byEcosystem[ecosystem]
			set.entries = append(set.entries, endpoint)
			catalog.byEcosystem[ecosystem] = set
			if u.Scheme == "http" {
				log.Warnf("Custom registry endpoint %q uses plain HTTP; traffic is inspectable but not encrypted", u.String())
			}
		}
	}

	return catalog, nil
}

func newBuiltInRegistryCatalog() *RegistryCatalog {
	return &RegistryCatalog{
		byEcosystem: map[packagev1.Ecosystem]registrySet{
			packagev1.Ecosystem_ECOSYSTEM_NPM:  {entries: append([]registryEndpoint(nil), npmRegistryEndpoints...)},
			packagev1.Ecosystem_ECOSYSTEM_PYPI: {entries: append([]registryEndpoint(nil), pypiRegistryEndpoints...)},
		},
	}
}

func (c *RegistryCatalog) registrySet(ecosystem packagev1.Ecosystem) registrySet {
	if c == nil {
		return registrySet{}
	}
	set := c.byEcosystem[ecosystem]
	return registrySet{entries: append([]registryEndpoint(nil), set.entries...)}
}

func (c *RegistryCatalog) IsKnownRegistryRequest(ctx *proxy.RequestContext) bool {
	if ctx == nil || ctx.Hostname == "" {
		return false
	}
	hostname := normalizeHostnameWithOptionalPort(ctx.Hostname)
	if wellKnownGoHosts[hostname] {
		return true
	}

	scheme := "https"
	port := ctx.Port
	if ctx.Method != http.MethodConnect && ctx.URL != nil && ctx.URL.Scheme != "" {
		scheme = registryurl.NormalizeScheme(ctx.URL.Scheme)
		if port == "" {
			port = ctx.URL.Port()
		}
	}
	port, valid := registryurl.EffectivePort(scheme, port)
	for _, set := range c.byEcosystem {
		for index := range set.entries {
			endpoint := &set.entries[index]
			_, matches := endpointMatchesHostname(endpoint, hostname)
			if !matches {
				continue
			}
			if endpoint.Source == registrySourceBuiltIn {
				return true
			}
			if valid && endpointMatchesOrigin(endpoint, scheme, port) {
				return true
			}
		}
	}
	return false
}

func (c *RegistryCatalog) builtInForHostname(hostname string) *registryEndpoint {
	hostname = normalizeHostnameWithOptionalPort(hostname)
	var best *registryEndpoint
	for _, ecosystem := range []packagev1.Ecosystem{
		packagev1.Ecosystem_ECOSYSTEM_NPM,
		packagev1.Ecosystem_ECOSYSTEM_PYPI,
	} {
		set := c.byEcosystem[ecosystem]
		for index := range set.entries {
			endpoint := &set.entries[index]
			if endpoint.Source != registrySourceBuiltIn {
				continue
			}
			exact, matches := endpointMatchesHostname(endpoint, hostname)
			if !matches {
				continue
			}
			if exact {
				return endpoint
			}
			if best == nil || len(endpoint.Host) > len(best.Host) {
				best = endpoint
			}
		}
	}
	return best
}

func registryEcosystem(ecosystem string) packagev1.Ecosystem {
	switch ecosystem {
	case "npm":
		return packagev1.Ecosystem_ECOSYSTEM_NPM
	case "pypi":
		return packagev1.Ecosystem_ECOSYSTEM_PYPI
	default:
		panic(fmt.Sprintf("unsupported validated registry ecosystem %q", ecosystem))
	}
}

func customRegistryParser(ecosystem packagev1.Ecosystem, u *url.URL) registryURLParser {
	if ecosystem == packagev1.Ecosystem_ECOSYSTEM_PYPI {
		return pypiCustomParser{baseEndsInSimple: pypiBaseEndsInSimple(u.EscapedPath())}
	}
	return npmParser{}
}

func builtInRegistryEndpoint(host string, analyze bool, parser registryURLParser) registryEndpoint {
	return registryEndpoint{
		Name:    host,
		Source:  registrySourceBuiltIn,
		Scope:   registryScopeHostAndSubdomains,
		Host:    registryurl.NormalizeHostname(host),
		Analyze: analyze,
		Parser:  parser,
	}
}
