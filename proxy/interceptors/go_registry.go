package interceptors

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/proxy"
)

var goRegistryDomains = registryConfigMap{
	"proxy.golang.org": {
		Host:                 "proxy.golang.org",
		SupportedForAnalysis: true,
		Parser:               goProxyParser{},
	},
}

// GoRegistryInterceptor intercepts Go module registry requests and analyzes packages for malware
// It embeds baseRegistryInterceptor to reuse ecosystem agnostic functionality
type GoRegistryInterceptor struct {
	baseRegistryInterceptor
}

var _ proxy.Interceptor = (*GoRegistryInterceptor)(nil)
var _ proxy.MITMDecider = (*GoRegistryInterceptor)(nil)

// NewGoRegistryInterceptor creates a new Go registry interceptor
func NewGoRegistryInterceptor(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
) *GoRegistryInterceptor {
	return &GoRegistryInterceptor{
		baseRegistryInterceptor: baseRegistryInterceptor{
			analyzer:         analyzer,
			cache:            cache,
			statsCollector:   statsCollector,
			confirmationChan: confirmationChan,
			circuitBreaker:   newAnalyzerCircuitBreaker("malysis-analyzer-go"),
		},
	}
}

// Name returns the interceptor name for logging
func (i *GoRegistryInterceptor) Name() string {
	return "go-registry-interceptor"
}

func (i *GoRegistryInterceptor) ShouldMITM(ctx *proxy.RequestContext) bool {
	config := goRegistryDomains.GetConfigForHostname(ctx.Hostname)
	if config == nil {
		return false
	}

	return config.SupportedForAnalysis
}

// ShouldIntercept determines if this interceptor should handle the given request
func (i *GoRegistryInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	return goRegistryDomains.ContainsHostname(ctx.Hostname)
}

// HandleRequest processes the request and returns response action
// We take a fail-open approach here, allowing requests that we can't parse the package information from the URL.
func (i *GoRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Handling Go registry request: %s", ctx.RequestID, ctx.URL.Path)

	config := goRegistryDomains.GetConfigForHostname(ctx.Hostname)
	if config == nil {
		log.Warnf("[%s] No registry config found for hostname: %s", ctx.RequestID, ctx.Hostname)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if !config.SupportedForAnalysis {
		log.Debugf("[%s] Skipping analysis for %s registry (not supported for analysis): %s",
			ctx.RequestID, config.Host, ctx.URL.String())
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	pkgInfo, err := config.Parser.ParseURL(ctx.URL.Path)
	if err != nil {
		log.Warnf("[%s] Failed to parse Go registry URL %s for %s: %v",
			ctx.RequestID, ctx.URL.Path, config.Host, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if !pkgInfo.IsFileDownload() {
		log.Debugf("[%s] Skipping analysis for non-zip request: %s", ctx.RequestID, pkgInfo.GetName())
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	result, err := i.analyzePackage(
		ctx,
		packagev1.Ecosystem_ECOSYSTEM_GO,
		pkgInfo.GetName(),
		pkgInfo.GetVersion(),
	)
	if err != nil {
		log.Errorf("[%s] Failed to analyze package %s@%s: %v", ctx.RequestID, pkgInfo.GetName(), pkgInfo.GetVersion(), err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_GO, pkgInfo.GetName(), pkgInfo.GetVersion(), result)
}
