package interceptors

import (
	"net/url"

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
	artifacts       *artifactIndex
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
	registries := registryConfigSet{entries: builtInRegistryConfigs(npmRegistryDomains)}
	customRegistries, err := customRegistryConfigs(execContext, "npm")
	if err != nil {
		return nil, err
	}
	registries.entries = append(registries.entries, customRegistries...)
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
		artifacts:       newArtifactIndex(),
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
	return registryHostSupportsAnalysis(i.registries, ctx.Hostname)
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
		// advertise a safe identity for another package's real tarball path
		// and have PMG analyze and allow the wrong bytes.
		return i.handleArtifact(ctx, pkgInfo.GetName(), pkgInfo.GetVersion())
	}

	// Canonical parsing failed, or the path isn't shaped like a real npm
	// tarball (a metadata request, or a parser that never resolves file
	// downloads). Only now fall back to the registry-scoped artifact index,
	// which resolves non-standard artifact paths advertised by metadata
	// discovery. config.Name is empty for built-in registries, so this never
	// matches them: artifactIndex.Get requires a non-empty registry name.
	if identity, ok := i.artifacts.Get(config.Name, requestURL); ok {
		return i.handleArtifact(ctx, identity.Name, identity.Version)
	}

	if parseErr != nil {
		if config.Name == "" {
			log.Warnf("[%s] Failed to parse NPM registry URL %s for %s: %v",
				ctx.RequestID, ctx.URL.Path, config.Host, parseErr)
		} else {
			// Custom registries see far more non-package traffic (health
			// checks, auth, search) under their configured prefix, and the
			// path itself may embed a signed token, so this stays at debug
			// level and never logs the raw path.
			log.Debugf("[%s] Failed to parse NPM registry URL for custom registry %q: %v", ctx.RequestID, config.Name, parseErr)
		}
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	depCooldownConfig := pmgconfig.Get().Config.DependencyCooldown

	if !pkgInfo.IsFileDownload() {
		return i.handleMetadataRequest(ctx, config, pkgInfo, requestURL, depCooldownConfig)
	}

	// A file-download parse without a complete identity, and no index match:
	// nothing reliable to analyze against.
	return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
}

// handleMetadataRequest applies dependency cooldown, artifact discovery, or
// both to a package metadata request, depending on whether cooldown is
// enabled and whether the request targets a custom registry. Discovery runs
// before cooldown so it always sees the upstream packument, never a
// cooldown-stripped one.
func (i *NpmRegistryInterceptor) handleMetadataRequest(
	ctx *proxy.RequestContext,
	config *registryConfig,
	pkgInfo packageInfo,
	requestURL *url.URL,
	depCooldownConfig pmgconfig.DependencyCooldownConfig,
) (*proxy.InterceptorResponse, error) {
	trustedAllVersions := pmgconfig.IsTrustedPackageAllVersions(packagev1.Ecosystem_ECOSYSTEM_NPM, pkgInfo.GetName())

	var cooldownModifier proxy.ResponseModifierFunc
	if depCooldownConfig.Enabled && !trustedAllVersions {
		cooldownResp, err := i.cooldownHandler.HandleMetadataRequest(ctx, pkgInfo.GetName(), depCooldownConfig.Days, i.execContext.PinnedVersions[pkgInfo.GetName()])
		if err != nil {
			return nil, err
		}
		if cooldownResp.Action == proxy.ActionModifyResponse {
			cooldownModifier = cooldownResp.ResponseModifier
		}
	}

	if config.Name == "" {
		if cooldownModifier == nil {
			log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, pkgInfo.GetName())
			return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
		}
		return &proxy.InterceptorResponse{Action: proxy.ActionModifyResponse, ResponseModifier: cooldownModifier}, nil
	}

	// Discovery needs a parseable, always-fresh body regardless of whether
	// cooldown also runs: cooldown only normalizes these headers itself when
	// it registers its own modifier (enabled, not trusted, not skip-listed),
	// so without this a discovery-only request could otherwise arrive
	// compressed or be answered with a bodyless 304.
	forceUncompressedNonConditionalResponse(ctx.Headers)

	discovery := npmMetadataDiscoveryModifier(ctx, i.artifacts, i.registries, config.Name, requestURL)
	return &proxy.InterceptorResponse{
		Action:           proxy.ActionModifyResponse,
		ResponseModifier: chainResponseModifiers(discovery, cooldownModifier),
	}, nil
}

// handleArtifact runs the shared trust, analysis, and verdict pipeline for a
// package artifact download, regardless of whether its identity came from
// canonical URL parsing or from the registry-scoped artifact index.
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
