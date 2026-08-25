package interceptors

import (
	"net/url"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
)

var pypiRegistryEndpoints = []registryEndpoint{
	builtInRegistryEndpoint("files.pythonhosted.org", true, pypiFilesParser{}),
	builtInRegistryEndpoint("pypi.org", true, pypiOrgParser{}),
	builtInRegistryEndpoint("test.pypi.org", false, pypiOrgParser{}),
	builtInRegistryEndpoint("test-files.pythonhosted.org", false, pypiFilesParser{}),
}

// PypiRegistryInterceptor intercepts PyPI registry requests and analyzes packages for malware
// It embeds baseRegistryInterceptor to reuse ecosystem agnostic functionality
type PypiRegistryInterceptor struct {
	baseRegistryInterceptor
	registryRequestMatcher
	cooldownHandler *pypiCooldownHandler
	artifacts       *artifactIndex
}

var _ proxy.Interceptor = (*PypiRegistryInterceptor)(nil)
var _ proxy.MITMDecider = (*PypiRegistryInterceptor)(nil)

func newPypiRegistryInterceptor(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
	execContext InterceptorContext,
	registries registrySet,
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
		registryRequestMatcher: registryRequestMatcher{registries: registries},
		cooldownHandler:        newPypiCooldownHandler(statsCollector),
		artifacts:              newArtifactIndex(),
	}
}

// Name returns the interceptor name for logging
func (i *PypiRegistryInterceptor) Name() string {
	return "pypi-registry-interceptor"
}

// HandleRequest runs the shared registry flow with PyPI's artifact and
// metadata handlers.
func (i *PypiRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	return handleRegistryRequest(ctx, i.registries, "PyPI", i)
}

// resolveIndexedArtifact resolves an opaque download URL to an identity a
// prior metadata response advertised for the same registry.
func (i *PypiRegistryInterceptor) resolveIndexedArtifact(registryName string, requestURL *url.URL) (artifactIdentity, bool) {
	return i.artifacts.Get(registryName, requestURL)
}

// handleMetadataRequest applies cooldown, artifact discovery, or both to a
// metadata request. Discovery runs before cooldown so it always sees the
// upstream index. Cooldown applies only to Simple API requests, since pip
// uses those, not the JSON API, for version resolution.
func (i *PypiRegistryInterceptor) handleMetadataRequest(
	ctx *proxy.RequestContext,
	endpoint *registryEndpoint,
	pkgInfo packageInfo,
	requestURL *url.URL,
) (*proxy.InterceptorResponse, error) {
	depCooldownConfig := pmgconfig.Get().Config.DependencyCooldown
	isSimpleAPIRequest := pypiIsSimpleAPIMetadataRequest(pkgInfo)

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

	// Discovery applies only to a Simple API request on a custom registry.
	// The JSON API and built-in registries never populate the index, so
	// cooldown alone (or nothing) applies to them.
	if endpoint.Source != registrySourceCustom || !isSimpleAPIRequest {
		if cooldownModifier == nil {
			log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, pkgInfo.GetName())
			return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
		}
		return &proxy.InterceptorResponse{Action: proxy.ActionModifyResponse, ResponseModifier: cooldownModifier}, nil
	}

	// Discovery needs a parseable, always-fresh body even when cooldown does
	// not run its own modifier, or the response could arrive compressed or
	// as a bodyless 304.
	forceUncompressedNonConditionalResponse(ctx.Headers)

	discovery := pypiMetadataDiscoveryModifier(ctx, i.artifacts, i.registries, endpoint.Name, requestURL)
	return &proxy.InterceptorResponse{
		Action:           proxy.ActionModifyResponse,
		ResponseModifier: chainResponseModifiers(discovery, cooldownModifier),
	}, nil
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
