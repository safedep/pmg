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

	compiledRegistries *compiledCustomRegistries

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
	registryErr      error
}

// NewInterceptorFactory creates a new interceptor factory with shared dependencies
func NewInterceptorFactory(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
	execContext InterceptorContext,
) *InterceptorFactory {
	compiled, err := compileCustomRegistries(execContext.Registries)
	if err == nil {
		execContext.compiledRegistries = compiled
		warnPlainHTTPRegistryEndpoints(compiled.plainHTTPEndpoints)
	}
	return &InterceptorFactory{
		analyzer:         analyzer,
		cache:            cache,
		statsCollector:   statsCollector,
		confirmationChan: confirmationChan,
		execContext:      execContext,
		registryErr:      err,
	}
}

// CustomRegistryHosts returns the validated exact hosts used by the audit interceptor.
func (f *InterceptorFactory) CustomRegistryHosts() ([]string, error) {
	if f.registryErr != nil {
		return nil, f.registryErr
	}
	return append([]string(nil), f.execContext.compiledRegistries.hosts...), nil
}

type compiledCustomRegistries struct {
	configs            map[string][]*registryConfig
	hosts              []string
	plainHTTPEndpoints []string
}

func compileCustomRegistries(registries []config.ProxyRegistryConfig) (*compiledCustomRegistries, error) {
	if err := config.ValidateProxyRegistries(registries); err != nil {
		return nil, fmt.Errorf("invalid custom proxy registries: %w", err)
	}

	compiled := &compiledCustomRegistries{configs: make(map[string][]*registryConfig)}
	hosts := make(map[string]struct{})
	for _, registry := range registries {
		var parser registryURLParser
		switch registry.Ecosystem {
		case "npm":
			parser = npmParser{}
		case "pypi":
			parser = pypiOrgParser{}
		}
		for _, endpoint := range registry.Endpoints {
			u, err := normalizedRegistryEndpoint(endpoint.URL)
			if err != nil {
				return nil, fmt.Errorf("invalid custom proxy registry %q endpoint: %w", registry.Name, err)
			}
			compiled.configs[registry.Ecosystem] = append(compiled.configs[registry.Ecosystem], &registryConfig{
				Name:                 registry.Name,
				Host:                 u.Hostname(),
				Scheme:               u.Scheme,
				Port:                 u.Port(),
				BasePath:             u.EscapedPath(),
				MatchSubdomains:      false,
				SupportedForAnalysis: true,
				Parser:               parser,
			})
			hosts[u.Hostname()] = struct{}{}
			if u.Scheme == "http" {
				compiled.plainHTTPEndpoints = append(compiled.plainHTTPEndpoints, u.String())
			}
		}
	}

	for host := range hosts {
		compiled.hosts = append(compiled.hosts, host)
	}
	sort.Strings(compiled.hosts)
	return compiled, nil
}

func normalizedRegistryEndpoint(rawURL string) (*url.URL, error) {
	normalized, err := registryurl.Normalize(rawURL)
	if err != nil {
		return nil, err
	}
	return url.Parse(normalized)
}

func customRegistryConfigs(execContext InterceptorContext, ecosystem string) []*registryConfig {
	compiled := execContext.compiledRegistries
	if compiled == nil {
		var err error
		compiled, err = compileCustomRegistries(execContext.Registries)
		if err != nil {
			return nil
		}
	}
	return compiled.configs[ecosystem]
}

func warnPlainHTTPRegistryEndpoints(endpoints []string) {
	for _, endpoint := range endpoints {
		log.Warnf("Custom registry endpoint %q uses plain HTTP; traffic is inspectable but not encrypted", endpoint)
	}
}

// CreateInterceptor creates an interceptor for the specified ecosystem
// Returns an error if the ecosystem is not supported for proxy-based interception
func (f *InterceptorFactory) CreateInterceptor(ecosystem packagev1.Ecosystem) (proxy.Interceptor, error) {
	if f.registryErr != nil {
		return nil, f.registryErr
	}
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
