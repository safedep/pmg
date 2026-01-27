package interceptors

import (
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/proxy"
)

// InterceptorFactory creates ecosystem-specific interceptors for the proxy
type InterceptorFactory struct {
	analyzer         analyzer.PackageVersionAnalyzer
	cache            AnalysisCache
	statsCollector   *AnalysisStatsCollector
	confirmationChan chan *ConfirmationRequest
}

// NewInterceptorFactory creates a new interceptor factory with shared dependencies
func NewInterceptorFactory(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
) *InterceptorFactory {
	return &InterceptorFactory{
		analyzer:         analyzer,
		cache:            cache,
		statsCollector:   statsCollector,
		confirmationChan: confirmationChan,
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
		), nil

	default:
		return nil, fmt.Errorf("proxy-based interception not yet supported for ecosystem: %s", ecosystem.String())
	}
}

// SupportedEcosystems returns a list of ecosystems that support proxy-based interception
func SupportedEcosystems() []packagev1.Ecosystem {
	return []packagev1.Ecosystem{
		packagev1.Ecosystem_ECOSYSTEM_NPM,
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
