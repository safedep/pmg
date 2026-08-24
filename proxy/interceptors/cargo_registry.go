package interceptors

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
)

const (
	cargoIndexHost  = "index.crates.io"
	cargoStaticHost = "static.crates.io"
)

// cargoRegistryEndpoints are the fixed crates.io hosts. The crates.io API
// host is deliberately absent. Cargo uses the API host only for
// authenticated operations (publish, yank, owner, search), so that traffic
// is tunneled opaquely and PMG never sees registry tokens.
var cargoRegistryEndpoints = []registryEndpoint{
	builtInRegistryEndpoint(cargoIndexHost, true, cargoIndexParser{}),
	builtInRegistryEndpoint(cargoStaticHost, true, cargoDownloadParser{}),
}

// CargoRegistryInterceptor intercepts crates.io sparse-index and .crate
// download requests and analyzes crates for malware. It embeds
// baseRegistryInterceptor to reuse ecosystem agnostic functionality.
type CargoRegistryInterceptor struct {
	baseRegistryInterceptor
	registryRequestMatcher
	cooldownHandler *cargoCooldownHandler
}

var _ proxy.Interceptor = (*CargoRegistryInterceptor)(nil)
var _ proxy.MITMDecider = (*CargoRegistryInterceptor)(nil)

func newCargoRegistryInterceptor(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
	execContext InterceptorContext,
	registries registrySet,
) *CargoRegistryInterceptor {
	return &CargoRegistryInterceptor{
		baseRegistryInterceptor: baseRegistryInterceptor{
			analyzer:         analyzer,
			cache:            cache,
			statsCollector:   statsCollector,
			confirmationChan: confirmationChan,
			circuitBreaker:   newAnalyzerCircuitBreaker("malysis-analyzer-cargo"),
			execContext:      execContext,
		},
		registryRequestMatcher: registryRequestMatcher{registries: registries},
		cooldownHandler:        newCargoCooldownHandler(statsCollector, execContext.CargoIndexBaseURL),
	}
}

func (i *CargoRegistryInterceptor) Name() string {
	return "cargo-registry-interceptor"
}

// HandleRequest runs the shared registry flow with cargo's artifact and
// metadata handlers.
func (i *CargoRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	return handleRegistryRequest(ctx, i.registries, "Cargo", i)
}

// handleMetadataRequest applies dependency cooldown to a sparse-index
// request. The registry config.json passes through untouched.
func (i *CargoRegistryInterceptor) handleMetadataRequest(
	ctx *proxy.RequestContext,
	pkgInfo packageInfo,
) (*proxy.InterceptorResponse, error) {
	info, ok := pkgInfo.(*cargoCrateInfo)
	if !ok || info.requestType != cargoRequestIndex {
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	depCooldownConfig := pmgconfig.Get().Config.DependencyCooldown
	if !depCooldownConfig.Enabled ||
		pmgconfig.IsTrustedPackageAllVersions(packagev1.Ecosystem_ECOSYSTEM_CARGO, info.name) {
		log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, ctx.URL.Path)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.cooldownHandler.HandleIndexRequest(ctx, info.name, depCooldownConfig.Days, i.execContext.PinnedVersions[info.name])
}

// handleArtifact runs the cooldown, trust, analysis, and verdict pipeline
// for a .crate download.
func (i *CargoRegistryInterceptor) handleArtifact(ctx *proxy.RequestContext, name, version string) (*proxy.InterceptorResponse, error) {
	depCooldownConfig := pmgconfig.Get().Config.DependencyCooldown
	if depCooldownConfig.Enabled {
		if resp, handled := i.cooldownHandler.CheckCrateDownload(ctx, name, version, depCooldownConfig.Days); handled {
			return resp, nil
		}
	}

	if resp, ok := i.fastAllow(ctx, packagev1.Ecosystem_ECOSYSTEM_CARGO, name, version); ok {
		return resp, nil
	}

	result, err := i.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_CARGO, name, version)
	if err != nil {
		log.Errorf("[%s] Failed to analyze package %s@%s: %v", ctx.RequestID, name, version, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_CARGO, name, version, result)
}
