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

// ecosystemSpec is everything the catalog needs to support one ecosystem.
// Adding an ecosystem means adding a config.ProxyRegistryEcosystem constant
// and one entry here.
type ecosystemSpec struct {
	proto           packagev1.Ecosystem
	builtIns        []registryEndpoint
	newCustomParser func(basePath string) registryURLParser
}

var proxyEcosystems = map[config.ProxyRegistryEcosystem]ecosystemSpec{
	config.ProxyRegistryEcosystemNpm: {
		proto:    packagev1.Ecosystem_ECOSYSTEM_NPM,
		builtIns: npmRegistryEndpoints,
		newCustomParser: func(string) registryURLParser {
			return npmParser{}
		},
	},
	config.ProxyRegistryEcosystemPypi: {
		proto:    packagev1.Ecosystem_ECOSYSTEM_PYPI,
		builtIns: pypiRegistryEndpoints,
		newCustomParser: func(basePath string) registryURLParser {
			return pypiCustomParser{baseEndsInSimple: pypiBaseEndsInSimple(basePath)}
		},
	},
	config.ProxyRegistryEcosystemGo: {
		proto:    packagev1.Ecosystem_ECOSYSTEM_GO,
		builtIns: goRegistryEndpoints,
		newCustomParser: func(string) registryURLParser {
			return goProxyParser{}
		},
	},
}

// goProxyRegistryName names the endpoints that come from the GOPROXY of a
// `pmg go` run in logs. They are not proxy.registries entries.
const goProxyRegistryName = "GOPROXY"

type RegistryCatalog struct {
	byEcosystem map[packagev1.Ecosystem]registrySet
}

// NewRegistryCatalog builds the catalog from the built-in registries, the
// configured proxy.registries and goProxyURLs, the module proxies from the
// GOPROXY of a `pmg go` run. proxy.registries entries must be valid. A
// GOPROXY entry that PMG cannot analyze, or that a registry already covers,
// is skipped: go still uses it, and PMG must not refuse a run over it.
func NewRegistryCatalog(registries []config.ProxyRegistryConfig, goProxyURLs []string) (*RegistryCatalog, error) {
	// Keep this boundary self-validating because callers can construct a
	// catalog directly without going through the global config loader.
	normalized, err := config.NormalizeProxyRegistries(registries)
	if err != nil {
		return nil, fmt.Errorf("invalid custom proxy registries: %w", err)
	}

	catalog := newBuiltInRegistryCatalog()
	for _, configured := range normalized {
		if _, ok := proxyEcosystems[configured.Ecosystem]; !ok {
			return nil, fmt.Errorf("invalid custom proxy registry %q: unsupported ecosystem %q", configured.RegistryName, configured.Ecosystem)
		}
		if catalog.builtInCoversHostname(configured.Host) {
			return nil, fmt.Errorf("invalid custom %s registry %q endpoint: host %q is covered by a built-in registry",
				configured.Ecosystem, configured.RegistryName, configured.Host)
		}
		catalog.addCustomEndpoint(configured)
	}

	for _, rawURL := range goProxyURLs {
		entry, err := config.NormalizeRegistryEndpoint(goProxyRegistryName, config.ProxyRegistryEcosystemGo, rawURL)
		if err != nil {
			log.Warnf("GOPROXY entry %q is not analyzed: %v", rawURL, err)
			continue
		}
		if baseURL, err := url.Parse(entry.URL); err == nil && catalog.registrySet(packagev1.Ecosystem_ECOSYSTEM_GO).MatchURL(baseURL) != nil {
			continue
		}
		if catalog.builtInCoversHostname(entry.Host) {
			log.Warnf("GOPROXY entry %q is not analyzed: host %q is covered by a built-in registry", rawURL, entry.Host)
			continue
		}
		if existing := config.FindNestedEndpoint(entry, normalized); existing != nil {
			log.Warnf("GOPROXY entry %q is not analyzed: it overlaps the %s registry endpoint %q", rawURL, existing.Ecosystem, existing.URL)
			continue
		}
		normalized = append(normalized, entry)
		catalog.addCustomEndpoint(entry)
	}

	return catalog, nil
}

func (c *RegistryCatalog) addCustomEndpoint(configured config.NormalizedRegistryEndpoint) {
	spec := proxyEcosystems[configured.Ecosystem]
	endpoint := registryEndpoint{
		Name:     configured.RegistryName,
		Source:   registrySourceCustom,
		Scope:    registryScopeOrigin,
		Scheme:   configured.Scheme,
		Host:     configured.Host,
		Port:     configured.Port,
		BasePath: configured.BasePath,
		Analyze:  true,
		Parser:   spec.newCustomParser(configured.BasePath),
	}
	set := c.byEcosystem[spec.proto]
	set.entries = append(set.entries, endpoint)
	c.byEcosystem[spec.proto] = set
	if configured.Scheme == "http" {
		log.Warnf("Custom registry endpoint %q uses plain HTTP. Anyone on the network path can read and change this traffic", configured.URL)
	}
}

func newBuiltInRegistryCatalog() *RegistryCatalog {
	byEcosystem := make(map[packagev1.Ecosystem]registrySet, len(proxyEcosystems)+1)
	for _, spec := range proxyEcosystems {
		byEcosystem[spec.proto] = registrySet{entries: append([]registryEndpoint(nil), spec.builtIns...)}
	}
	// Cargo has built-in endpoints only. proxy.registries does not support
	// custom cargo registries yet, so cargo is not in the spec table.
	byEcosystem[packagev1.Ecosystem_ECOSYSTEM_CARGO] = registrySet{entries: append([]registryEndpoint(nil), cargoRegistryEndpoints...)}
	return &RegistryCatalog{byEcosystem: byEcosystem}
}

func (c *RegistryCatalog) registrySet(ecosystem packagev1.Ecosystem) registrySet {
	if c == nil {
		return registrySet{}
	}
	set := c.byEcosystem[ecosystem]
	return registrySet{entries: append([]registryEndpoint(nil), set.entries...)}
}

// IsKnownRegistryRequest reports whether a request targets a known registry
// origin. It deliberately ignores paths: audit host observations are
// suppressed for the whole origin, not per endpoint base path. This is a
// third matching semantic next to MatchConnect (MITM decisions) and
// MatchURL (per-request endpoint resolution). Do not fold it into either.
func (c *RegistryCatalog) IsKnownRegistryRequest(ctx *proxy.RequestContext) bool {
	if ctx == nil || ctx.Hostname == "" {
		return false
	}
	hostname := normalizeHostnameWithOptionalPort(ctx.Hostname)

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

func (c *RegistryCatalog) builtInCoversHostname(hostname string) bool {
	hostname = normalizeHostnameWithOptionalPort(hostname)
	for _, set := range c.byEcosystem {
		for index := range set.entries {
			endpoint := &set.entries[index]
			if endpoint.Source != registrySourceBuiltIn {
				continue
			}
			if _, matches := endpointMatchesHostname(endpoint, hostname); matches {
				return true
			}
		}
	}
	return false
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
