package interceptors

import (
	"errors"
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

	// GoProxyURLs are the module proxies from the GOPROXY of a `pmg go` run,
	// with no credentials. They join the registry catalog as Go endpoints.
	GoProxyURLs []string

	// GoProxyUpstreamOrigin replaces the scheme and host of the out-of-band
	// Go .info fetch. Empty means the origin of the request. Set by the
	// hermetic proxy E2E tests.
	GoProxyUpstreamOrigin string

	// CargoIndexBaseURL overrides the upstream sparse-index base URL used for
	// out-of-band publish-time fetches. Empty means the public crates.io
	// sparse index; set by the hermetic proxy E2E tests.
	CargoIndexBaseURL string
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
	catalog, err := NewRegistryCatalog(registries, execContext.GoProxyURLs)
	if err != nil {
		var conflict *config.GoProxyConflictError
		if errors.As(err, &conflict) {
			return nil, config.NewGoProxyConflictError(conflict)
		}
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

// GoProxyNotices names the GOPROXY entries of this run that PMG does not
// analyze.
func (f *InterceptorFactory) GoProxyNotices() []string {
	return f.registries.GoProxyNotices()
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
		return newGoRegistryInterceptor(
			f.analyzer,
			f.cache,
			f.statsCollector,
			f.confirmationChan,
			f.execContext,
			f.registries.registrySet(packagev1.Ecosystem_ECOSYSTEM_GO),
		), nil

	case packagev1.Ecosystem_ECOSYSTEM_CARGO:
		return newCargoRegistryInterceptor(
			f.analyzer,
			f.cache,
			f.statsCollector,
			f.confirmationChan,
			f.execContext,
			f.registries.registrySet(packagev1.Ecosystem_ECOSYSTEM_CARGO),
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
		packagev1.Ecosystem_ECOSYSTEM_CARGO,
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
