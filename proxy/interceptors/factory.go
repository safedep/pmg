package interceptors

import (
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
)

// InterceptorContext carries per-execution data from the CLI command into
// the interceptor layer. Unlike the factory's long-lived dependencies
// (analyzer, cache, stats), this holds context specific to the current run.
type InterceptorContext struct {
	PinnedVersions map[string]string

	// GoProxyBaseURLs maps module-proxy hostnames from the user's effective
	// GOPROXY to their upstream base URL (scheme + host + optional path
	// prefix). Go registry routing is derived dynamically from GOPROXY and
	// remains separate from the npm/PyPI registry catalog.
	GoProxyBaseURLs map[string]string
}

// InterceptorFactory creates ecosystem-specific interceptors for the proxy
type InterceptorFactory struct {
	analyzer         analyzer.PackageVersionAnalyzer
	cache            AnalysisCache
	statsCollector   *AnalysisStatsCollector
	confirmationChan chan *ConfirmationRequest
	execContext      InterceptorContext
	registries       *RegistryCatalog
}

// NewInterceptorFactory creates a new interceptor factory with shared dependencies
func NewInterceptorFactory(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
	execContext InterceptorContext,
	registries []config.ProxyRegistryConfig,
) (*InterceptorFactory, error) {
	catalog, err := NewRegistryCatalog(registries)
	if err != nil {
		return nil, config.NewInvalidProxyRegistriesError(err)
	}
	return &InterceptorFactory{
		analyzer:         analyzer,
		cache:            cache,
		statsCollector:   statsCollector,
		confirmationChan: confirmationChan,
		execContext:      execContext,
		registries:       catalog,
	}, nil
}

// CreateInterceptor creates an interceptor for the specified ecosystem
// Returns an error if the ecosystem is not supported for proxy-based interception
func (f *InterceptorFactory) CreateInterceptor(ecosystem packagev1.Ecosystem) (proxy.Interceptor, error) {
	switch ecosystem {
	case packagev1.Ecosystem_ECOSYSTEM_NPM:
		return newNpmRegistryInterceptor(
			f.analyzer,
			f.cache,
			f.statsCollector,
			f.confirmationChan,
			f.execContext,
			f.registries.registrySet(packagev1.Ecosystem_ECOSYSTEM_NPM),
		), nil

	case packagev1.Ecosystem_ECOSYSTEM_PYPI:
		return newPypiRegistryInterceptor(
			f.analyzer,
			f.cache,
			f.statsCollector,
			f.confirmationChan,
			f.execContext,
			f.registries.registrySet(packagev1.Ecosystem_ECOSYSTEM_PYPI),
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

func (f *InterceptorFactory) CreateInterceptors(ecosystems ...packagev1.Ecosystem) ([]proxy.Interceptor, error) {
	result := make([]proxy.Interceptor, 0, len(ecosystems)+1)
	for _, ecosystem := range ecosystems {
		interceptor, err := f.CreateInterceptor(ecosystem)
		if err != nil {
			return nil, fmt.Errorf("create interceptor for %s: %w", ecosystem.String(), err)
		}
		result = append(result, interceptor)
	}
	return append(result, NewAuditLoggerInterceptor(f.registries)), nil
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
