package interceptors

import (
	"net/url"

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
	artifacts       *artifactIndex
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
		artifacts:              newArtifactIndex(),
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

// resolveIndexedArtifact resolves an opaque download URL to an identity a
// prior metadata response advertised for the same registry.
func (i *NpmRegistryInterceptor) resolveIndexedArtifact(registryName string, requestURL *url.URL) (artifactIdentity, bool) {
	return i.artifacts.Get(registryName, requestURL)
}

// handleMetadataRequest applies cooldown, artifact discovery, or both to a
// metadata request. Discovery runs before cooldown so it always sees the
// upstream packument.
func (i *NpmRegistryInterceptor) handleMetadataRequest(
	ctx *proxy.RequestContext,
	endpoint *registryEndpoint,
	pkgInfo packageInfo,
	requestURL *url.URL,
) (*proxy.InterceptorResponse, error) {
	depCooldownConfig := pmgconfig.Get().Config.DependencyCooldown
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

	// Built-in registries never populate the index, so discovery is a no-op
	// for them. Cooldown alone (or nothing) applies.
	if endpoint.Source != registrySourceCustom {
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

	discovery := npmMetadataDiscoveryModifier(ctx, i.artifacts, i.registries, endpoint.Name, requestURL)
	return &proxy.InterceptorResponse{
		Action:           proxy.ActionModifyResponse,
		ResponseModifier: chainResponseModifiers(discovery, cooldownModifier),
	}, nil
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
