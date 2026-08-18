package interceptors

import (
	"net/url"
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
	registries      registryConfigSet
	artifacts       *artifactIndex
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
		artifacts:       newArtifactIndex(),
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

	// Skip analysis for registries that are not supported for analysis
	config := match.Config
	if !config.SupportedForAnalysis {
		log.Debugf("[%s] Skipping analysis for %s registry (not supported for analysis): %s",
			ctx.RequestID, config.Host, ctx.URL.String())
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	requestURL := registryAbsoluteRequestURL(ctx)

	// Parse URL using registry-specific strategy
	pkgInfo, parseErr := config.Parser.ParseURL(match.RelativePath)

	if parseErr == nil && packageInfoHasCompleteIdentity(pkgInfo) {
		// Canonical parsing already resolves this exact URL to a complete
		// identity. This is authoritative and must never be overridden by a
		// metadata-discovered mapping: otherwise a compromised registry could
		// advertise a safe identity for another package's real artifact path
		// and have PMG analyze and allow the wrong bytes.
		return i.handleArtifact(ctx, pkgInfo.GetName(), pkgInfo.GetVersion())
	}

	// Canonical parsing failed, or the path isn't shaped like a real PyPI
	// artifact (a metadata request, or a parser that never resolves file
	// downloads). Only now fall back to the registry-scoped artifact index,
	// which resolves non-standard artifact paths advertised by metadata
	// discovery. config.Name is empty for built-in registries, so this never
	// matches them: artifactIndex.Get requires a non-empty registry name.
	if identity, ok := i.artifacts.Get(config.Name, requestURL); ok {
		return i.handleArtifact(ctx, identity.Name, identity.Version)
	}

	if parseErr != nil {
		if config.Name == "" {
			log.Warnf("[%s] Failed to parse PyPI registry URL %s for %s: %v",
				ctx.RequestID, ctx.URL.Path, config.Host, parseErr)
		} else {
			// Custom registries see far more non-package traffic (health
			// checks, auth, search) under their configured prefix, and the
			// path itself may embed a signed token, so this stays at debug
			// level and never logs the raw path.
			log.Debugf("[%s] Failed to parse PyPI registry URL for custom registry %q: %v", ctx.RequestID, config.Name, parseErr)
		}
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if !pkgInfo.IsFileDownload() {
		return i.handleMetadataRequest(ctx, config, pkgInfo, requestURL)
	}

	// A file-download parse without a complete identity, and no index match:
	// nothing reliable to analyze against.
	return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
}

// handleMetadataRequest applies dependency cooldown, artifact discovery, or
// both to a package metadata request, depending on whether cooldown applies
// and whether the request targets a custom registry. Discovery runs before
// cooldown so it always sees the upstream index, never a cooldown-stripped
// one. Cooldown only ever applies to Simple API requests, since pip uses
// those for version resolution; JSON API requests have a different response
// shape and pip does not use them for installs.
func (i *PypiRegistryInterceptor) handleMetadataRequest(
	ctx *proxy.RequestContext,
	config *registryConfig,
	pkgInfo packageInfo,
	requestURL *url.URL,
) (*proxy.InterceptorResponse, error) {
	depCooldownConfig := pmgconfig.Get().Config.DependencyCooldown
	isSimpleAPIRequest := pypiIsSimpleAPIMetadataRequest(ctx, config, pkgInfo)

	var cooldownModifier proxy.ResponseModifierFunc
	if depCooldownConfig.Enabled && isSimpleAPIRequest {
		canonicalName := denormalizePyPIPackageName(pkgInfo.GetName())
		if !pmgconfig.IsTrustedPackageAllVersions(packagev1.Ecosystem_ECOSYSTEM_PYPI, canonicalName) {
			cooldownResp, err := i.cooldownHandler.HandleMetadataRequest(ctx, pkgInfo.GetName(), depCooldownConfig.Days, i.execContext.PinnedVersions[pkgInfo.GetName()])
			if err != nil {
				return nil, err
			}
			if cooldownResp.Action == proxy.ActionModifyResponse {
				cooldownModifier = cooldownResp.ResponseModifier
			}
		}
	}

	if config.Name == "" || !isSimpleAPIRequest {
		if cooldownModifier == nil {
			log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, pkgInfo.GetName())
			return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
		}
		return &proxy.InterceptorResponse{Action: proxy.ActionModifyResponse, ResponseModifier: cooldownModifier}, nil
	}

	// Discovery needs a parseable, always-fresh body regardless of whether
	// cooldown also runs: cooldown only normalizes these headers itself when
	// it registers its own modifier (enabled, not trusted), so without this a
	// discovery-only request could otherwise arrive compressed or be
	// answered with a bodyless 304.
	forceUncompressedNonConditionalResponse(ctx.Headers)

	discovery := pypiMetadataDiscoveryModifier(ctx, i.artifacts, i.registries, config.Name, requestURL)
	return &proxy.InterceptorResponse{
		Action:           proxy.ActionModifyResponse,
		ResponseModifier: chainResponseModifiers(discovery, cooldownModifier),
	}, nil
}

// pypiIsSimpleAPIMetadataRequest decides whether a metadata request is Simple
// API shaped, the only shape pip uses for version resolution and the only
// one cooldown and discovery apply to.
//
// A built-in registry's base path is always "/simple/..." or "/pypi/..."
// verbatim, so the absolute request path decides it exactly as before a
// custom registry could exist. A custom registry can mount its Simple API
// under any prefix, so the absolute path can no longer be trusted; whether
// config.Parser resolved a Simple-shaped or JSON-shaped result decides it
// instead.
func pypiIsSimpleAPIMetadataRequest(ctx *proxy.RequestContext, config *registryConfig, pkgInfo packageInfo) bool {
	if config.Name == "" {
		return strings.HasPrefix(ctx.URL.Path, "/simple/")
	}
	info, ok := pkgInfo.(*pypiPackageInfo)
	return ok && info.IsSimpleAPI()
}

// handleArtifact runs the shared trust, analysis, and verdict pipeline for a
// package artifact download, regardless of whether its identity came from
// canonical URL parsing or from the registry-scoped artifact index. Canonical
// (denormalized) name is used for the trust check; the parsed name is kept
// for analyzePackage so malware analysis sees the original form.
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
