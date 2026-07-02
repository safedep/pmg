package interceptors

import (
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
)

// goToolchainModule is the module path Go uses to auto-download toolchains
// (GOTOOLCHAIN=auto). Toolchain zips are verified by go against the checksum
// database regardless of GOPRIVATE/GONOSUMDB, and downloads fail closed when
// GOSUMDB=off, so PMG passes them through on Go's own verification instead of
// treating them as ordinary (never-flagged) modules.
const goToolchainModule = "golang.org/toolchain"

// GoRegistryInterceptor intercepts Go module proxy requests and analyzes
// module zips for malware. Unlike npm/PyPI, the registry hosts are not fixed:
// they come from the user's effective GOPROXY via
// InterceptorContext.GoProxyHosts. sum.golang.org is never in that set, so
// checksum-database traffic is tunneled, not MITM'd.
type GoRegistryInterceptor struct {
	baseRegistryInterceptor
	domains         registryConfigMap
	cooldownHandler *goCooldownHandler
}

var _ proxy.Interceptor = (*GoRegistryInterceptor)(nil)
var _ proxy.MITMDecider = (*GoRegistryInterceptor)(nil)

func NewGoRegistryInterceptor(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
	execContext InterceptorContext,
) *GoRegistryInterceptor {
	domains := registryConfigMap{}
	for _, host := range execContext.GoProxyHosts {
		domains[host] = &registryConfig{
			Host:                 host,
			SupportedForAnalysis: true,
			Parser:               goProxyParser{},
		}
	}

	return &GoRegistryInterceptor{
		baseRegistryInterceptor: baseRegistryInterceptor{
			analyzer:         analyzer,
			cache:            cache,
			statsCollector:   statsCollector,
			confirmationChan: confirmationChan,
			circuitBreaker:   newAnalyzerCircuitBreaker("malysis-analyzer-go"),
			execContext:      execContext,
		},
		domains:         domains,
		cooldownHandler: newGoCooldownHandler(statsCollector),
	}
}

func (i *GoRegistryInterceptor) Name() string {
	return "go-registry-interceptor"
}

func (i *GoRegistryInterceptor) ShouldMITM(ctx *proxy.RequestContext) bool {
	config := i.domains.GetConfigForHostname(ctx.Hostname)
	if config == nil {
		return false
	}

	return config.SupportedForAnalysis
}

func (i *GoRegistryInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	return i.domains.ContainsHostname(ctx.Hostname)
}

// HandleRequest processes the request and returns response action.
// We take a fail-open approach here, allowing requests that we can't parse the
// package information from the URL — but an unparseable .zip means an
// unanalyzed source download, so that case is logged loudly.
func (i *GoRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Handling Go module proxy request: %s", ctx.RequestID, ctx.URL.Path)

	config := i.domains.GetConfigForHostname(ctx.Hostname)
	if config == nil {
		log.Warnf("[%s] No registry config found for hostname: %s", ctx.RequestID, ctx.Hostname)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	pkgInfo, err := config.Parser.ParseURL(ctx.URL.Path)
	if err != nil {
		if strings.HasSuffix(ctx.URL.Path, ".zip") {
			log.Warnf("[%s] Failed to parse Go module proxy zip URL %s: %v — download allowed without analysis",
				ctx.RequestID, ctx.URL.Path, err)
		} else {
			log.Debugf("[%s] Failed to parse Go module proxy URL %s: %v", ctx.RequestID, ctx.URL.Path, err)
		}
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	info, ok := pkgInfo.(*goModuleInfo)
	if !ok {
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if info.requestType == goRequestSumDB {
		log.Debugf("[%s] Allowing proxied checksum-database request: %s", ctx.RequestID, ctx.URL.Path)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if info.name == goToolchainModule {
		if info.IsFileDownload() {
			log.Infof("[%s] Allowing Go toolchain download %s@%s (verified by Go's checksum database)",
				ctx.RequestID, info.name, info.version)
		}
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	depCooldownConfig := pmgconfig.Get().Config.DependencyCooldown

	if !info.IsFileDownload() {
		if info.requestType == goRequestInfo && info.version != "" && depCooldownConfig.Enabled {
			return i.cooldownHandler.HandleInfoRequest(ctx, info.name, info.version)
		}

		log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, info.name)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if depCooldownConfig.Enabled {
		if resp, handled := i.cooldownHandler.CheckZipDownload(ctx, info.name, info.version, depCooldownConfig.Days); handled {
			return resp, nil
		}
	}

	if resp, ok := i.fastAllow(ctx, packagev1.Ecosystem_ECOSYSTEM_GO, info.name, info.version); ok {
		return resp, nil
	}

	result, err := i.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_GO, info.name, info.version)
	if err != nil {
		log.Errorf("[%s] Failed to analyze package %s@%s: %v", ctx.RequestID, info.name, info.version, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_GO, info.name, info.version, result)
}
