package interceptors

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
)

var npmRegistryEndpoints = []registryEndpoint{
	builtInRegistryEndpoint("registry.npmjs.org", true, npmParser{}),
	builtInRegistryEndpoint("registry.yarnpkg.com", true, npmParser{}),
	builtInRegistryEndpoint("npm.pkg.github.com", false, npmGithubParser{}),
	builtInRegistryEndpoint("pkg-npm.githubusercontent.com", false, npmGithubBlobParser{}),
}

// NpmRegistryInterceptor intercepts NPM registry requests and analyzes packages for malware
// It embeds baseRegistryInterceptor to reuse ecosystem agnostic functionality
type NpmRegistryInterceptor struct {
	baseRegistryInterceptor
	registryRequestMatcher
	cooldownHandler *npmCooldownHandler
}

var _ proxy.Interceptor = (*NpmRegistryInterceptor)(nil)
var _ proxy.MITMDecider = (*NpmRegistryInterceptor)(nil)

func newNpmRegistryInterceptor(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
	execContext InterceptorContext,
	registries registrySet,
) *NpmRegistryInterceptor {
	return &NpmRegistryInterceptor{
		baseRegistryInterceptor: baseRegistryInterceptor{
			analyzer:         analyzer,
			cache:            cache,
			statsCollector:   statsCollector,
			confirmationChan: confirmationChan,
			circuitBreaker:   newAnalyzerCircuitBreaker("malysis-analyzer-npm"),
			execContext:      execContext,
		},
		registryRequestMatcher: registryRequestMatcher{registries: registries},
		cooldownHandler:        newNpmCooldownHandler(statsCollector),
	}
}

// Name returns the interceptor name for logging
func (i *NpmRegistryInterceptor) Name() string {
	return "npm-registry-interceptor"
}

// HandleRequest runs the shared registry flow with npm's artifact and
// metadata handlers.
func (i *NpmRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	return handleRegistryRequest(ctx, i.registries, "NPM", i)
}

// handleMetadataRequest applies dependency cooldown to a metadata request.
func (i *NpmRegistryInterceptor) handleMetadataRequest(
	ctx *proxy.RequestContext,
	pkgInfo packageInfo,
) (*proxy.InterceptorResponse, error) {
	depCooldownConfig := pmgconfig.Get().Config.DependencyCooldown
	if !depCooldownConfig.Enabled ||
		pmgconfig.IsTrustedPackageAllVersions(packagev1.Ecosystem_ECOSYSTEM_NPM, pkgInfo.GetName()) {
		log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, pkgInfo.GetName())
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.cooldownHandler.HandleMetadataRequest(ctx, pkgInfo.GetName(), depCooldownConfig.Days, i.execContext.PinnedVersions[pkgInfo.GetName()])
}

// handleArtifact runs the trust, analysis, and verdict pipeline for an
// artifact download identified by canonical URL parsing.
func (i *NpmRegistryInterceptor) handleArtifact(ctx *proxy.RequestContext, name, version string) (*proxy.InterceptorResponse, error) {
	if resp, ok := i.fastAllow(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, name, version); ok {
		return resp, nil
	}

	result, err := i.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, name, version)
	if err != nil {
		return i.failClosed(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, name, version, err), nil
	}

	return i.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, name, version, result)
}
