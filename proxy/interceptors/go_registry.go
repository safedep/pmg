package interceptors

import (
	"sync"
	"time"

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

// zipVerdictTTL is how long a module zip verdict is reused. go asks again for
// a zip that failed, seconds later, in the same command. The reuse keeps that
// retry from recording the module twice and from asking the user twice. A
// later client of a long-running proxy gets a fresh verdict, so its block is
// recorded and audited too.
const zipVerdictTTL = time.Minute

// goRegistryEndpoints are the built-in Go hosts. The public module proxy is
// analyzed. The checksum database is a known registry host that is never
// decrypted. Module proxies from GOPROXY or proxy.registries are custom
// endpoints.
var goRegistryEndpoints = []registryEndpoint{
	builtInRegistryEndpoint(pmgconfig.GoModuleProxyHost, true, goProxyParser{}),
	builtInRegistryEndpoint(pmgconfig.GoChecksumDatabaseHost, false, goProxyParser{}),
}

// GoRegistryInterceptor intercepts Go module proxy requests and analyzes
// module zips for malware.
type GoRegistryInterceptor struct {
	baseRegistryInterceptor
	registryRequestMatcher
	cooldownHandler *goCooldownHandler

	now           func() time.Time
	zipVerdictsMu sync.Mutex
	zipVerdicts   map[string]zipVerdict
}

type zipVerdict struct {
	response *proxy.InterceptorResponse
	expires  time.Time
}

var _ proxy.Interceptor = (*GoRegistryInterceptor)(nil)
var _ proxy.MITMDecider = (*GoRegistryInterceptor)(nil)

func newGoRegistryInterceptor(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
	execContext InterceptorContext,
	registries registrySet,
) *GoRegistryInterceptor {
	return &GoRegistryInterceptor{
		baseRegistryInterceptor: baseRegistryInterceptor{
			analyzer:         analyzer,
			cache:            cache,
			statsCollector:   statsCollector,
			confirmationChan: confirmationChan,
			circuitBreaker:   newAnalyzerCircuitBreaker("malysis-analyzer-go"),
			execContext:      execContext,
		},
		registryRequestMatcher: registryRequestMatcher{registries: registries},
		cooldownHandler:        newGoCooldownHandler(statsCollector, execContext.GoProxyUpstreamOrigin),
		now:                    time.Now,
		zipVerdicts:            map[string]zipVerdict{},
	}
}

func (i *GoRegistryInterceptor) Name() string {
	return "go-registry-interceptor"
}

// HandleRequest runs the shared registry flow with Go's artifact and metadata
// handlers.
func (i *GoRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	return handleRegistryRequest(ctx, i.registries, "Go", i)
}

// handleMetadataRequest passes checksum-database traffic through untouched
// and captures the publish time from .info for the cooldown check of the zip.
func (i *GoRegistryInterceptor) handleMetadataRequest(
	ctx *proxy.RequestContext,
	_ *registryMatch,
	pkgInfo packageInfo,
) (*proxy.InterceptorResponse, error) {
	info, ok := pkgInfo.(*goModuleInfo)
	if !ok || info.requestType != goRequestInfo || info.version == "" || info.name == goToolchainModule {
		log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, ctx.URL.Path)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if !pmgconfig.Get().Config.DependencyCooldown.Enabled {
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.cooldownHandler.HandleInfoRequest(ctx, info.name, info.version)
}

// handleArtifact runs the security controls for a module zip and reuses a
// recent verdict for a repeated request.
func (i *GoRegistryInterceptor) handleArtifact(
	ctx *proxy.RequestContext,
	match *registryMatch,
	name, version string,
) (*proxy.InterceptorResponse, error) {
	if name == goToolchainModule {
		log.Infof("[%s] Allowing Go toolchain download %s@%s (verified by Go's checksum database)",
			ctx.RequestID, name, version)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	key := goModuleVersionKey(name, version)
	if resp := i.recentZipVerdict(key); resp != nil {
		log.Debugf("[%s] Reusing verdict for repeated zip request: %s", ctx.RequestID, key)
		return resp, nil
	}

	resp, memoize, err := i.handleZipDownload(ctx, match, name, version)
	if err != nil {
		return resp, err
	}
	if memoize {
		i.rememberZipVerdict(key, resp)
	}
	return resp, nil
}

// handleZipDownload runs dependency cooldown, then trusted/insecure
// fast-allow, then malware analysis. memoize is false only when the outcome is
// a fail-open allow after an analyzer error, so a retried request gets another
// chance to be analyzed.
func (i *GoRegistryInterceptor) handleZipDownload(
	ctx *proxy.RequestContext,
	match *registryMatch,
	name, version string,
) (*proxy.InterceptorResponse, bool, error) {
	cooldown := pmgconfig.Get().Config.DependencyCooldown
	if cooldown.Enabled {
		if resp, handled := i.cooldownHandler.CheckZipDownload(ctx, match.Endpoint.BasePath, name, version, cooldown.Days); handled {
			return resp, true, nil
		}
	}

	if resp, ok := i.fastAllow(ctx, packagev1.Ecosystem_ECOSYSTEM_GO, name, version); ok {
		return resp, true, nil
	}

	result, err := i.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_GO, name, version)
	if err != nil {
		log.Errorf("[%s] Failed to analyze package %s@%s: %v", ctx.RequestID, name, version, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, false, nil
	}

	resp, err := i.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_GO, name, version, result)
	return resp, err == nil, err
}

func (i *GoRegistryInterceptor) recentZipVerdict(key string) *proxy.InterceptorResponse {
	i.zipVerdictsMu.Lock()
	defer i.zipVerdictsMu.Unlock()

	verdict, ok := i.zipVerdicts[key]
	if !ok || !i.now().Before(verdict.expires) {
		return nil
	}
	return verdict.response
}

func (i *GoRegistryInterceptor) rememberZipVerdict(key string, resp *proxy.InterceptorResponse) {
	i.zipVerdictsMu.Lock()
	defer i.zipVerdictsMu.Unlock()

	now := i.now()
	for k, verdict := range i.zipVerdicts {
		if !now.Before(verdict.expires) {
			delete(i.zipVerdicts, k)
		}
	}
	i.zipVerdicts[key] = zipVerdict{response: resp, expires: now.Add(zipVerdictTTL)}
}
