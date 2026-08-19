package interceptors

import (
	"net/http"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
)

var pypiRegistryDomains = registryConfigMap{
	"files.pythonhosted.org": {
		Host:                 "files.pythonhosted.org",
		SupportedForAnalysis: true,
		Parser:               pypiFilesParser{},
	},
	"pypi.org": {
		Host:                 "pypi.org",
		SupportedForAnalysis: true,
		Parser:               pypiOrgParser{},
	},
	// Test PyPI instance
	"test.pypi.org": {
		Host:                 "test.pypi.org",
		SupportedForAnalysis: false, // Skip analysis for test PyPI
		Parser:               pypiOrgParser{},
	},
	"test-files.pythonhosted.org": {
		Host:                 "test-files.pythonhosted.org",
		SupportedForAnalysis: false, // Skip analysis for test PyPI files
		Parser:               pypiFilesParser{},
	},
}

// PypiRegistryInterceptor intercepts PyPI registry requests and analyzes packages for malware
// It embeds baseRegistryInterceptor to reuse ecosystem agnostic functionality
type PypiRegistryInterceptor struct {
	baseRegistryInterceptor
	cooldownHandler *pypiCooldownHandler
	registries      registryConfigSet
}

var _ proxy.Interceptor = (*PypiRegistryInterceptor)(nil)
var _ proxy.MITMDecider = (*PypiRegistryInterceptor)(nil)

// NewPypiRegistryInterceptor creates a new PyPI registry interceptor
func NewPypiRegistryInterceptor(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
	execContext InterceptorContext,
) (*PypiRegistryInterceptor, error) {
	// Re-key pinned versions to the normalized form (lowercase, underscores→hyphens)
	// so lookups by URL-parsed package name match correctly.
	normalizedPinned := make(map[string]string, len(execContext.PinnedVersions))
	for name, version := range execContext.PinnedVersions {
		normalizedPinned[denormalizePyPIPackageName(name)] = version
	}
	execContext.PinnedVersions = normalizedPinned
	registries := registryConfigSet{entries: builtInRegistryConfigs(pypiRegistryDomains)}
	customRegistries, err := customRegistryConfigs(execContext, "pypi")
	if err != nil {
		return nil, err
	}
	registries.entries = append(registries.entries, customRegistries...)

	return &PypiRegistryInterceptor{
		baseRegistryInterceptor: baseRegistryInterceptor{
			analyzer:         analyzer,
			cache:            cache,
			statsCollector:   statsCollector,
			confirmationChan: confirmationChan,
			circuitBreaker:   newAnalyzerCircuitBreaker("malysis-analyzer-pypi"),
			execContext:      execContext,
		},
		cooldownHandler: newPypiCooldownHandler(statsCollector),
		registries:      registries,
	}, nil
}

// Name returns the interceptor name for logging
func (i *PypiRegistryInterceptor) Name() string {
	return "pypi-registry-interceptor"
}

func (i *PypiRegistryInterceptor) ShouldMITM(ctx *proxy.RequestContext) bool {
	if ctx == nil {
		return false
	}
	return registryHostSupportsAnalysis(i.registries, ctx.Hostname)
}

// ShouldIntercept determines if this interceptor should handle the given request
func (i *PypiRegistryInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	return registryRequestMatch(i.registries, ctx) != nil
}

// HandleRequest processes the request and returns response action
// We take a fail-open approach here, allowing requests that we can't parse the package information from the URL.
func (i *PypiRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Handling PyPI registry request: %s", ctx.RequestID, ctx.URL.Path)

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
		if config.Name == "" {
			log.Warnf("[%s] Failed to parse PyPI registry URL %s for %s: %v",
				ctx.RequestID, ctx.URL.Path, config.Host, parseErr)
		} else {
			// Custom registries see far more non-package traffic under their
			// configured prefix, and the path can embed a signed token, so
			// this logs at debug level only.
			log.Debugf("[%s] Failed to parse PyPI registry URL for custom registry %q: %v", ctx.RequestID, config.Name, parseErr)
		}
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
// Cooldown applies only to Simple API requests, since pip uses those, not
// the JSON API, for version resolution.
func (i *PypiRegistryInterceptor) handleMetadataRequest(
	ctx *proxy.RequestContext,
	pkgInfo packageInfo,
) (*proxy.InterceptorResponse, error) {
	depCooldownConfig := pmgconfig.Get().Config.DependencyCooldown
	if !depCooldownConfig.Enabled || !pypiIsSimpleAPIMetadataRequest(pkgInfo) ||
		pmgconfig.IsTrustedPackageAllVersions(packagev1.Ecosystem_ECOSYSTEM_PYPI, denormalizePyPIPackageName(pkgInfo.GetName())) {
		log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, pkgInfo.GetName())
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.cooldownHandler.HandleMetadataRequest(ctx, pkgInfo.GetName(), depCooldownConfig.Days, i.execContext.PinnedVersions[pkgInfo.GetName()])
}

// pypiIsSimpleAPIMetadataRequest reports whether a metadata request is
// Simple API shaped, the only shape cooldown applies to. The parsers set
// the flag for both built-in and custom registries (parseSimpleAPIURL sets
// it, parseJSONAPIURL leaves it false), so the JSON API stays excluded
// from cooldown everywhere.
func pypiIsSimpleAPIMetadataRequest(pkgInfo packageInfo) bool {
	info, ok := pkgInfo.(*pypiPackageInfo)
	return ok && info.IsSimpleAPI()
}

// handleArtifact runs the trust, analysis, and verdict pipeline for an
// artifact download identified by canonical URL parsing. The canonical
// name is used for the trust check; the parsed name is kept for
// analyzePackage.
func (i *PypiRegistryInterceptor) handleArtifact(ctx *proxy.RequestContext, name, version string) (*proxy.InterceptorResponse, error) {
	canonicalName := denormalizePyPIPackageName(name)
	if resp, ok := i.fastAllow(ctx, packagev1.Ecosystem_ECOSYSTEM_PYPI, canonicalName, version); ok {
		return resp, nil
	}

	result, err := i.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_PYPI, name, version)
	if err != nil {
		log.Errorf("[%s] Failed to analyze package %s@%s: %v", ctx.RequestID, name, version, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_PYPI, name, version, result)
}
