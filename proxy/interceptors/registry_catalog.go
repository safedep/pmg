package interceptors

import (
	"fmt"
	"net/http"
	"strings"

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
}

type RegistryCatalog struct {
	byEcosystem map[packagev1.Ecosystem]registrySet
}

func NewRegistryCatalog(registries []config.ProxyRegistryConfig) (*RegistryCatalog, error) {
	// Keep this boundary self-validating because callers can construct a
	// catalog directly without going through the global config loader.
	normalized, err := config.NormalizeProxyRegistries(registries)
	if err != nil {
		return nil, fmt.Errorf("invalid custom proxy registries: %w", err)
	}

	catalog := newBuiltInRegistryCatalog()

	for _, configured := range normalized {
		spec, ok := proxyEcosystems[configured.Ecosystem]
		if !ok {
			return nil, fmt.Errorf("invalid custom proxy registry %q: unsupported ecosystem %q", configured.RegistryName, configured.Ecosystem)
		}
		if catalog.builtInCoversHostname(configured.Host) {
			return nil, fmt.Errorf("invalid custom %s registry %q endpoint: host %q is covered by the built-in npm/PyPI registries",
				configured.Ecosystem, configured.RegistryName, configured.Host)
		}
		// The Go hosts are not catalog entries (Go routing derives from
		// GOPROXY per run), so cover them here. A custom endpoint on them
		// would decrypt Go module traffic, including sum.golang.org, which
		// PMG never MITMs.
		if reservedGoHost(configured.Host) {
			return nil, fmt.Errorf("invalid custom %s registry %q endpoint: host %q is reserved for PMG's built-in Go module handling",
				configured.Ecosystem, configured.RegistryName, configured.Host)
		}

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
		set := catalog.byEcosystem[spec.proto]
		set.entries = append(set.entries, endpoint)
		catalog.byEcosystem[spec.proto] = set
		if configured.Scheme == "http" {
			log.Warnf("Custom registry endpoint %q uses plain HTTP. Anyone on the network path can read and change this traffic", configured.URL)
		}
	}

	return catalog, nil
}

func newBuiltInRegistryCatalog() *RegistryCatalog {
	byEcosystem := make(map[packagev1.Ecosystem]registrySet, len(proxyEcosystems))
	for _, spec := range proxyEcosystems {
		byEcosystem[spec.proto] = registrySet{entries: append([]registryEndpoint(nil), spec.builtIns...)}
	}
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

// reservedGoHost reports whether a hostname belongs to the well-known Go
// module infrastructure, including subdomains. When PMG grows built-in Go
// registry endpoints, proxy.golang.org moves into that built-in set and this
// keeps guarding sum.golang.org.
func reservedGoHost(hostname string) bool {
	for host := range wellKnownGoHosts {
		if hostname == host || strings.HasSuffix(hostname, "."+host) {
			return true
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
