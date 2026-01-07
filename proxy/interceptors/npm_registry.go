package interceptors

import (
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/guard"
	"github.com/safedep/pmg/proxy"
)

var (
	npmRegistryDomains = []string{
		"registry.npmjs.org",
		"registry.yarnpkg.com",
	}
)

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
	confirmationChan chan *ConfirmationRequest,
	interaction guard.PackageManagerGuardInteraction,
) *NpmRegistryInterceptor {
	return &NpmRegistryInterceptor{
		baseRegistryInterceptor: baseRegistryInterceptor{
			analyzer:         analyzer,
			cache:            cache,
			confirmationChan: confirmationChan,
			interaction:      interaction,
		},
	}
}

// Name returns the interceptor name for logging
func (i *NpmRegistryInterceptor) Name() string {
	return "npm-registry-interceptor"
}

// ShouldIntercept determines if this interceptor should handle the given request
func (i *NpmRegistryInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	for _, domain := range npmRegistryDomains {
		if ctx.Hostname == domain || strings.HasSuffix(ctx.Hostname, "."+domain) {
			return true
		}
	}

	return false
}

// HandleRequest processes the request and returns response action
// We take a fail-open approach here, allowing requests that we can't parse the package information from the URL.
func (i *NpmRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Handling NPM registry request: %s", ctx.RequestID, ctx.URL.Path)

	pkgInfo, err := parseNpmRegistryURL(ctx.URL.Path)
	if err != nil {
		log.Warnf("[%s] Failed to parse NPM registry URL %s: %v", ctx.RequestID, ctx.URL.Path, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	// Only analyze tarball downloads (these have a specific version)
	// Metadata requests (without version) are allowed through
	if !pkgInfo.IsTarball {
		log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, pkgInfo.Name)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	result, err := i.baseRegistryInterceptor.analyzePackage(
		ctx,
		packagev1.Ecosystem_ECOSYSTEM_NPM,
		pkgInfo.Name,
		pkgInfo.Version,
	)
	if err != nil {
		log.Errorf("[%s] Failed to analyze package %s@%s: %v", ctx.RequestID, pkgInfo.Name, pkgInfo.Version, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.baseRegistryInterceptor.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, pkgInfo.Name, pkgInfo.Version, result)
}
