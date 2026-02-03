package interceptors

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
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
}

var _ proxy.Interceptor = (*NpmRegistryInterceptor)(nil)

// NewNpmRegistryInterceptor creates a new NPM registry interceptor
func NewNpmRegistryInterceptor(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
) *NpmRegistryInterceptor {
	return &NpmRegistryInterceptor{
		baseRegistryInterceptor: baseRegistryInterceptor{
			analyzer:         analyzer,
			cache:            cache,
			statsCollector:   statsCollector,
			confirmationChan: confirmationChan,
		},
	}
}

// Name returns the interceptor name for logging
func (i *NpmRegistryInterceptor) Name() string {
	return "npm-registry-interceptor"
}

// ShouldIntercept determines if this interceptor should handle the given request
func (i *NpmRegistryInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	return npmRegistryDomains.ContainsHostname(ctx.Hostname)
}

// HandleRequest processes the request and returns response action
// We take a fail-open approach here, allowing requests that we can't parse the package information from the URL.
func (i *NpmRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Handling NPM registry request: %s", ctx.RequestID, ctx.URL.Path)

	// Get registry configuration
	config := npmRegistryDomains.GetConfigForHostname(ctx.Hostname)
	if config == nil {
		// Shouldn't happen if ShouldIntercept is working correctly
		log.Warnf("[%s] No registry config found for hostname: %s", ctx.RequestID, ctx.Hostname)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	// Skip analysis for registries that are not supported for analysis
	if !config.SupportedForAnalysis {
		log.Debugf("[%s] Skipping analysis for %s registry (not supported for analysis): %s",
			ctx.RequestID, config.Host, ctx.URL.String())
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	// Parse URL using registry-specific strategy
	pkgInfo, err := config.Parser.ParseURL(ctx.URL.Path)
	if err != nil {
		log.Warnf("[%s] Failed to parse NPM registry URL %s for %s: %v",
			ctx.RequestID, ctx.URL.Path, config.Host, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	// Only analyze tarball downloads (these have a specific version)
	// Metadata requests (without version) are allowed through
	if !pkgInfo.IsFileDownload() {
		log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, pkgInfo.GetName())
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	result, err := i.baseRegistryInterceptor.analyzePackage(
		ctx,
		packagev1.Ecosystem_ECOSYSTEM_NPM,
		pkgInfo.GetName(),
		pkgInfo.GetVersion(),
	)
	if err != nil {
		log.Errorf("[%s] Failed to analyze package %s@%s: %v", ctx.RequestID, pkgInfo.GetName(), pkgInfo.GetVersion(), err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.baseRegistryInterceptor.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, pkgInfo.GetName(), pkgInfo.GetVersion(), result)
}
