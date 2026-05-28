package interceptors

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/proxy"
)

// goRegistryDomains lists standard Go module traffic seen in proxy mode.
// proxy.golang.org is MITM'd and analyzed; sum.golang.org is tunneled (not MITM'd)
// for checksum verification but still observed for telemetry on CONNECT and requests.
var goRegistryDomains = registryConfigMap{
	"proxy.golang.org": {
		Host:                 "proxy.golang.org",
		SupportedForAnalysis: true,
		Parser:               goProxyParser{},
	},
	"sum.golang.org": {
		Host:                 "sum.golang.org",
		SupportedForAnalysis: false,
		Parser:               sumdbParser{},
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
	execContext InterceptorContext,
) *GoRegistryInterceptor {
	return &GoRegistryInterceptor{
		baseRegistryInterceptor: baseRegistryInterceptor{
			analyzer:         analyzer,
			cache:            cache,
			statsCollector:   statsCollector,
			confirmationChan: confirmationChan,
			execContext:      execContext,
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

// HandleRequest processes the request and returns response action.
// We take a fail-open approach here, allowing requests that we can't parse the package information from the URL.
func (i *GoRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	config := goRegistryDomains.GetConfigForHostname(ctx.Hostname)
	if config == nil {
		log.Warnf("[%s] No registry config found for hostname: %s", ctx.RequestID, ctx.Hostname)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if !config.SupportedForAnalysis {
		return i.handleObservedGoTraffic(ctx, config)
	}

	log.Debugf("[%s] Handling Go module proxy request: %s", ctx.RequestID, ctx.URL.Path)

	pkgInfo, err := config.Parser.ParseURL(ctx.URL.Path)
	if err != nil {
		log.Warnf("[%s] Failed to parse Go registry URL %s for %s: %v",
			ctx.RequestID, ctx.URL.Path, config.Host, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if !goModuleShouldAnalyze(pkgInfo) {
		if info, ok := pkgInfo.(*goModuleInfo); ok {
			log.Debugf("[%s] Go proxy metadata only (%s); analysis runs on versioned requests (.info/.mod/.zip): %s",
				ctx.RequestID, info.requestType, pkgInfo.GetName())
		} else {
			log.Debugf("[%s] Skipping analysis for Go proxy request without version: %s", ctx.RequestID, pkgInfo.GetName())
		}

		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if info, ok := pkgInfo.(*goModuleInfo); ok {
		log.Debugf("[%s] Analyzing Go module %s@%s (%s)", ctx.RequestID, info.GetName(), info.GetVersion(), info.requestType)
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

func (i *GoRegistryInterceptor) handleObservedGoTraffic(
	ctx *proxy.RequestContext,
	config *registryConfig,
) (*proxy.InterceptorResponse, error) {
	path := ""
	if ctx.URL != nil {
		path = ctx.URL.Path
	}

	log.Debugf("[%s] Go checksum database traffic (observability): host=%s method=%s path=%s",
		ctx.RequestID, config.Host, ctx.Method, path)

	if path == "" || path == "/" {
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	pkgInfo, err := config.Parser.ParseURL(path)
	if err != nil {
		log.Debugf("[%s] Go checksum database URL not parsed (allowed): %s: %v",
			ctx.RequestID, path, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if info, ok := pkgInfo.(*sumdbModuleInfo); ok {
		switch info.requestType {
		case "lookup", "latest":
			if info.GetName() != "" {
				log.Debugf("[%s] Go sumdb %s: %s@%s", ctx.RequestID, info.requestType, info.GetName(), info.GetVersion())
			}
		case "supported":
			log.Debugf("[%s] Go sumdb capability check", ctx.RequestID)
		case "tile":
			log.Debugf("[%s] Go sumdb tile fetch: %s", ctx.RequestID, path)
		}
	}

	return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
}

// goModuleShouldAnalyze reports whether the proxy request has a resolved module version.
// Malysis analyzes by module@version, so @v/list and @latest are skipped; .info, .mod, and
// .zip are analyzed (cache dedupes repeats within one pmg invocation).
func goModuleShouldAnalyze(pkgInfo packageInfo) bool {
	info, ok := pkgInfo.(*goModuleInfo)
	if !ok {
		return false
	}

	return info.GetVersion() != ""
}
