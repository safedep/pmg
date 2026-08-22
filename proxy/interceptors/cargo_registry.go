package interceptors

import (
	"net/http"

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
// host is deliberately absent: cargo uses it only for authenticated
// operations (publish, yank, owner, search), so that traffic is tunneled
// opaquely and PMG never sees registry tokens.
var cargoRegistryEndpoints = []registryEndpoint{
	builtInRegistryEndpoint(cargoIndexHost, true, cargoIndexParser{}),
	builtInRegistryEndpoint(cargoStaticHost, true, cargoDownloadParser{}),
}

// CargoRegistryInterceptor intercepts crates.io sparse-index and .crate
// download requests and analyzes crates for malware. It embeds
// baseRegistryInterceptor to reuse ecosystem agnostic functionality.
type CargoRegistryInterceptor struct {
	baseRegistryInterceptor
	cooldownHandler *cargoCooldownHandler
	registries      registrySet
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
		cooldownHandler: newCargoCooldownHandler(statsCollector, execContext.CargoIndexBaseURL),
		registries:      registries,
	}
}

func (i *CargoRegistryInterceptor) Name() string {
	return "cargo-registry-interceptor"
}

func (i *CargoRegistryInterceptor) ShouldMITM(ctx *proxy.RequestContext) bool {
	if ctx == nil {
		return false
	}
	return registryHostSupportsAnalysis(i.registries, ctx.Hostname, ctx.Port)
}

func (i *CargoRegistryInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	return registryRequestMatch(i.registries, ctx) != nil
}

// HandleRequest processes the request and returns response action.
// We take a fail-open approach here, allowing requests that we can't parse the
// package information from the URL — but an unparseable .crate download means
// unanalyzed source, so that case is logged loudly.
func (i *CargoRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Handling cargo registry request: %s", ctx.RequestID, ctx.URL.Path)

	match := registryRequestMatch(i.registries, ctx)
	if match == nil {
		log.Warnf("[%s] No registry config found for hostname: %s", ctx.RequestID, ctx.Hostname)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	// Analysis and cooldown only ever act on reads; anything else passes
	// through untouched.
	if ctx.Method != http.MethodGet && ctx.Method != http.MethodHead {
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	endpoint := match.Endpoint
	pkgInfo, err := endpoint.Parser.ParseURL(match.RelativePath)
	if err != nil {
		if endpoint.Host == cargoStaticHost {
			log.Warnf("[%s] Failed to parse cargo download URL %s: %v — download allowed without analysis",
				ctx.RequestID, ctx.URL.Path, err)
		} else {
			log.Debugf("[%s] Failed to parse cargo registry URL %s: %v", ctx.RequestID, ctx.URL.Path, err)
		}
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	info, ok := pkgInfo.(*cargoCrateInfo)
	if !ok {
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	depCooldownConfig := pmgconfig.Get().Config.DependencyCooldown

	if !info.IsFileDownload() {
		if info.requestType == cargoRequestIndex && depCooldownConfig.Enabled {
			if pmgconfig.IsTrustedPackageAllVersions(packagev1.Ecosystem_ECOSYSTEM_CARGO, info.name) {
				return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
			}
			return i.cooldownHandler.HandleIndexRequest(ctx, info.name, depCooldownConfig.Days, i.execContext.PinnedVersions[info.name])
		}

		log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, ctx.URL.Path)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if depCooldownConfig.Enabled {
		if resp, handled := i.cooldownHandler.CheckCrateDownload(ctx, info.name, info.version, depCooldownConfig.Days); handled {
			return resp, nil
		}
	}

	if resp, ok := i.fastAllow(ctx, packagev1.Ecosystem_ECOSYSTEM_CARGO, info.name, info.version); ok {
		return resp, nil
	}

	result, err := i.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_CARGO, info.name, info.version)
	if err != nil {
		log.Errorf("[%s] Failed to analyze package %s@%s: %v", ctx.RequestID, info.name, info.version, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_CARGO, info.name, info.version, result)
}
