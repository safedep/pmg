package interceptors

import (
	"fmt"
	"net/url"
	"sort"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/registryurl"
	"github.com/safedep/pmg/proxy"
)

// InterceptorContext carries per-execution data from the CLI command into
// the interceptor layer. Unlike the factory's long-lived dependencies
// (analyzer, cache, stats), this holds context specific to the current run.
type InterceptorContext struct {
	PinnedVersions map[string]string
	Registries     []config.ProxyRegistryConfig

	// GoProxyBaseURLs maps module-proxy hostnames from the user's effective
	// GOPROXY to their upstream base URL (scheme + host + optional path
	// prefix). The Go interceptor MITMs and analyzes these hosts; Go is the
	// only ecosystem whose registry hosts are user-configurable rather than
	// fixed.
	GoProxyBaseURLs map[string]string
}

// InterceptorFactory creates ecosystem-specific interceptors for the proxy
type InterceptorFactory struct {
	analyzer         analyzer.PackageVersionAnalyzer
	cache            AnalysisCache
	statsCollector   *AnalysisStatsCollector
	confirmationChan chan *ConfirmationRequest
	execContext      InterceptorContext
}

// NewInterceptorFactory creates a new interceptor factory with shared dependencies
func NewInterceptorFactory(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
	execContext InterceptorContext,
) *InterceptorFactory {
	warnPlainHTTPRegistryEndpoints(execContext.Registries)
	return &InterceptorFactory{
		analyzer:         analyzer,
		cache:            cache,
		statsCollector:   statsCollector,
		confirmationChan: confirmationChan,
		execContext:      execContext,
	}
}

func CustomRegistryHosts(registries []config.ProxyRegistryConfig) []string {
	set := make(map[string]struct{})
	for _, registry := range registries {
		for _, endpoint := range registry.Endpoints {
			u, err := normalizedRegistryEndpoint(endpoint.URL)
			if err != nil {
				log.Warnf("Skipping invalid custom registry endpoint %q: %v", endpoint.URL, err)
				continue
			}
			set[u.Hostname()] = struct{}{}
		}
	}

	hosts := make([]string, 0, len(set))
	for host := range set {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

func customRegistryConfigs(registries []config.ProxyRegistryConfig, ecosystem string, parser registryURLParser) []*registryConfig {
	var configs []*registryConfig
	for _, registry := range registries {
		if registry.Ecosystem != ecosystem {
			continue
		}
		for _, endpoint := range registry.Endpoints {
			u, err := normalizedRegistryEndpoint(endpoint.URL)
			if err != nil {
				log.Warnf("Skipping invalid custom registry endpoint %q: %v", endpoint.URL, err)
				continue
			}
			configs = append(configs, &registryConfig{
				Name:                 registry.Name,
				Host:                 u.Hostname(),
				Scheme:               u.Scheme,
				Port:                 u.Port(),
				BasePath:             u.EscapedPath(),
				MatchSubdomains:      false,
				SupportedForAnalysis: true,
				Parser:               parser,
			})
		}
	}
	return configs
}

func normalizedRegistryEndpoint(rawURL string) (*url.URL, error) {
	normalized, err := registryurl.Normalize(rawURL)
	if err != nil {
		return nil, err
	}
	return url.Parse(normalized)
}

func warnPlainHTTPRegistryEndpoints(registries []config.ProxyRegistryConfig) {
	for _, registry := range registries {
		for _, endpoint := range registry.Endpoints {
			u, err := normalizedRegistryEndpoint(endpoint.URL)
			if err == nil && u.Scheme == "http" {
				log.Warnf("Custom registry endpoint %q uses plain HTTP; traffic is inspectable but not encrypted", endpoint.URL)
			}
		}
	}
}

// CreateInterceptor creates an interceptor for the specified ecosystem
// Returns an error if the ecosystem is not supported for proxy-based interception
func (f *InterceptorFactory) CreateInterceptor(ecosystem packagev1.Ecosystem) (proxy.Interceptor, error) {
	switch ecosystem {
	case packagev1.Ecosystem_ECOSYSTEM_NPM:
		return NewNpmRegistryInterceptor(
			f.analyzer,
			f.cache,
			f.statsCollector,
			f.confirmationChan,
			f.execContext,
		), nil

	case packagev1.Ecosystem_ECOSYSTEM_PYPI:
		return NewPypiRegistryInterceptor(
			f.analyzer,
			f.cache,
			f.statsCollector,
			f.confirmationChan,
			f.execContext,
		), nil

	case packagev1.Ecosystem_ECOSYSTEM_GO:
		return NewGoRegistryInterceptor(
			f.analyzer,
			f.cache,
			f.statsCollector,
			f.confirmationChan,
			f.execContext,
		), nil

	default:
		return nil, fmt.Errorf("proxy-based interception not yet supported for ecosystem: %s", ecosystem.String())
	}
}

// SupportedEcosystems returns a list of ecosystems that support proxy-based interception
func SupportedEcosystems() []packagev1.Ecosystem {
	return []packagev1.Ecosystem{
		packagev1.Ecosystem_ECOSYSTEM_NPM,
		packagev1.Ecosystem_ECOSYSTEM_PYPI,
		packagev1.Ecosystem_ECOSYSTEM_GO,
	}
}

// IsSupported checks if an ecosystem supports proxy-based interception
func IsSupported(ecosystem packagev1.Ecosystem) bool {
	for _, supported := range SupportedEcosystems() {
		if ecosystem == supported {
			return true
		}
	}

	return false
}
