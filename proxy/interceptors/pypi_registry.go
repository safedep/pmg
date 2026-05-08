package interceptors

import (
	"strings"

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
) *PypiRegistryInterceptor {
	// Re-key pinned versions to the normalized form (lowercase, underscores→hyphens)
	// so lookups by URL-parsed package name match correctly.
	normalizedPinned := make(map[string]string, len(execContext.PinnedVersions))
	for name, version := range execContext.PinnedVersions {
		normalizedPinned[denormalizePyPIPackageName(name)] = version
	}
	execContext.PinnedVersions = normalizedPinned

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
	}
}

// Name returns the interceptor name for logging
func (i *PypiRegistryInterceptor) Name() string {
	return "pypi-registry-interceptor"
}

func (i *PypiRegistryInterceptor) ShouldMITM(ctx *proxy.RequestContext) bool {
	config := pypiRegistryDomains.GetConfigForHostname(ctx.Hostname)
	if config == nil {
		return false
	}

	return config.SupportedForAnalysis
}

// ShouldIntercept determines if this interceptor should handle the given request
func (i *PypiRegistryInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	return pypiRegistryDomains.ContainsHostname(ctx.Hostname)
}

// HandleRequest processes the request and returns response action
// We take a fail-open approach here, allowing requests that we can't parse the package information from the URL.
func (i *PypiRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Handling PyPI registry request: %s", ctx.RequestID, ctx.URL.Path)

	// Get registry configuration
	config := pypiRegistryDomains.GetConfigForHostname(ctx.Hostname)
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
		log.Warnf("[%s] Failed to parse PyPI registry URL %s for %s: %v",
			ctx.RequestID, ctx.URL.Path, config.Host, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if !pkgInfo.IsFileDownload() {
		depCooldownConfig := pmgconfig.Get().Config.DependencyCooldown
		// Only apply cooldown to Simple API requests (/simple/{pkg}/) — pip uses these
		// for version resolution. JSON API requests (/pypi/{pkg}/json) are allowed through;
		// they have a different response structure and pip does not use them for installs.
		if depCooldownConfig.Enabled && strings.HasPrefix(ctx.URL.Path, "/simple/") {
			return i.cooldownHandler.HandleMetadataRequest(ctx, pkgInfo.GetName(), depCooldownConfig.Days, i.execContext.PinnedVersions[pkgInfo.GetName()])
		}

		log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, pkgInfo.GetName())
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	// Ensure we have both name and version for analysis
	if pkgInfo.GetName() == "" || pkgInfo.GetVersion() == "" {
		log.Warnf("[%s] Incomplete package info from URL %s: name=%s, version=%s",
			ctx.RequestID, ctx.URL.Path, pkgInfo.GetName(), pkgInfo.GetVersion())
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	// Get file type for logging if available
	fileType := ""
	if pypiInfo, ok := pkgInfo.(*pypiPackageInfo); ok {
		fileType = pypiInfo.FileType()
	}
	log.Debugf("[%s] Analyzing PyPI package: %s@%s (type: %s)",
		ctx.RequestID, pkgInfo.GetName(), pkgInfo.GetVersion(), fileType)

	result, err := i.analyzePackage(
		ctx,
		packagev1.Ecosystem_ECOSYSTEM_PYPI,
		pkgInfo.GetName(),
		pkgInfo.GetVersion(),
	)
	if err != nil {
		log.Errorf("[%s] Failed to analyze package %s@%s: %v", ctx.RequestID, pkgInfo.GetName(), pkgInfo.GetVersion(), err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_PYPI, pkgInfo.GetName(), pkgInfo.GetVersion(), result)
}
