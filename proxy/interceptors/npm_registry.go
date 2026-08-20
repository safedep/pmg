package interceptors

import (
	"net/http"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
)

var npmRegistryDomains = registryConfigMap{
	"registry.npmjs.org": {
		Host:                 "registry.npmjs.org",
		SupportedForAnalysis: true,
		Parser:               npmParser{},
	},
	"registry.yarnpkg.com": {
		Host:                 "registry.yarnpkg.com",
		SupportedForAnalysis: true,
		Parser:               npmParser{},
	},
	"npm.pkg.github.com": {
		Host:                 "npm.pkg.github.com",
		SupportedForAnalysis: false, // Skip analysis for now (private packages, auth complexity)
		Parser:               npmGithubParser{},
	},
	"pkg-npm.githubusercontent.com": {
		Host:                 "pkg-npm.githubusercontent.com",
		SupportedForAnalysis: false, // Skip analysis (blob storage, redirected downloads)
		Parser:               npmGithubBlobParser{},
	},
}

// NpmRegistryInterceptor intercepts NPM registry requests and analyzes packages for malware
// It embeds baseRegistryInterceptor to reuse ecosystem agnostic functionality
type NpmRegistryInterceptor struct {
	baseRegistryInterceptor
	cooldownHandler *npmCooldownHandler
	registries      registryConfigSet
}

var _ proxy.Interceptor = (*NpmRegistryInterceptor)(nil)
var _ proxy.MITMDecider = (*NpmRegistryInterceptor)(nil)

// NewNpmRegistryInterceptor creates a new NPM registry interceptor
func NewNpmRegistryInterceptor(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
	execContext InterceptorContext,
) (*NpmRegistryInterceptor, error) {
	registries := registryConfigSet{
		entries: append(builtInRegistryConfigs(npmRegistryDomains), execContext.CustomRegistries["npm"]...),
	}
	return &NpmRegistryInterceptor{
		baseRegistryInterceptor: baseRegistryInterceptor{
			analyzer:         analyzer,
			cache:            cache,
			statsCollector:   statsCollector,
			confirmationChan: confirmationChan,
			circuitBreaker:   newAnalyzerCircuitBreaker("malysis-analyzer-npm"),
			execContext:      execContext,
		},
		cooldownHandler: newNpmCooldownHandler(statsCollector),
		registries:      registries,
	}, nil
}

// Name returns the interceptor name for logging
func (i *NpmRegistryInterceptor) Name() string {
	return "npm-registry-interceptor"
}

func (i *NpmRegistryInterceptor) ShouldMITM(ctx *proxy.RequestContext) bool {
	if ctx == nil {
		return false
	}
	return registryHostSupportsAnalysis(i.registries, ctx.Hostname, ctx.Port)
}

// ShouldIntercept determines if this interceptor should handle the given request
func (i *NpmRegistryInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	return registryRequestMatch(i.registries, ctx) != nil
}

// HandleRequest processes the request and returns response action
// We take a fail-open approach here, allowing requests that we can't parse the package information from the URL.
func (i *NpmRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Handling NPM registry request: %s", ctx.RequestID, ctx.URL.Path)

	// Get registry configuration
	match := registryRequestMatch(i.registries, ctx)
	if match == nil {
		// Shouldn't happen if ShouldIntercept is working correctly
		log.Warnf("[%s] No registry config found for hostname: %s", ctx.RequestID, ctx.Hostname)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	// Analysis and cooldown only ever act on reads. Anything else (publish,
	// registry API calls) passes through untouched: no header rewrites, no
	// response modifiers.
	if ctx.Method != http.MethodGet && ctx.Method != http.MethodHead {
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	// Skip analysis for registries that are not supported for analysis
	config := match.Config
	if !config.SupportedForAnalysis {
		log.Debugf("[%s] Skipping analysis for %s registry (not supported for analysis): %s",
			ctx.RequestID, config.Host, ctx.URL.String())
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	// Parse URL using registry-specific strategy
	pkgInfo, parseErr := config.Parser.ParseURL(match.RelativePath)

	if parseErr == nil && packageInfoHasCompleteIdentity(pkgInfo) {
		return i.handleArtifact(ctx, pkgInfo.GetName(), pkgInfo.GetVersion())
	}

	if parseErr != nil {
		logRegistryParseFailure(ctx, config, "NPM", parseErr)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if !pkgInfo.IsFileDownload() {
		return i.handleMetadataRequest(ctx, pkgInfo)
	}

	// A file-download parse without a complete identity: nothing reliable
	// to analyze against. URLs that carry no identity at all (opaque
	// download URLs some registries serve) land here too and are allowed
	// without analysis.
	return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
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
		log.Errorf("[%s] Failed to analyze package %s@%s: %v", ctx.RequestID, name, version, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, name, version, result)
}
