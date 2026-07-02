package interceptors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/proxy"
)

// goCooldownHandler enforces dependency cooldown for Go modules. Unlike npm,
// there is no metadata to strip: the version go requests is already resolved
// by the time the proxy sees it. Instead the publish timestamp is captured
// from the .info response go fetches before each .zip, and an in-window .zip
// download is blocked with HTTP 403 — terminal, because the child GOPROXY is
// normalized to a comma-joined list with no direct fallback.
type goCooldownHandler struct {
	statsCollector *AnalysisStatsCollector

	mu           sync.Mutex
	publishTimes map[string]time.Time
}

func newGoCooldownHandler(statsCollector *AnalysisStatsCollector) *goCooldownHandler {
	return &goCooldownHandler{
		statsCollector: statsCollector,
		publishTimes:   map[string]time.Time{},
	}
}

func goModuleVersionKey(module, version string) string {
	return module + "@" + version
}

// HandleInfoRequest reads the .info response body without altering it and
// caches the version's publish time for the upcoming .zip request.
func (h *goCooldownHandler) HandleInfoRequest(ctx *proxy.RequestContext, module, version string) (*proxy.InterceptorResponse, error) {
	// Force an uncompressed, non-conditional response so the body is parseable
	// JSON rather than raw gzip bytes or an empty 304 (same as the npm
	// metadata modifier).
	ctx.Headers.Set("Accept-Encoding", "identity")
	ctx.Headers.Del("If-None-Match")
	ctx.Headers.Del("If-Modified-Since")

	modifier := func(statusCode int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		if statusCode != http.StatusOK {
			return statusCode, headers, body, nil
		}

		var info struct {
			Time time.Time `json:"Time"`
		}
		if err := json.Unmarshal(body, &info); err != nil || info.Time.IsZero() {
			log.Warnf("[%s] Cooldown: failed to parse publish time from .info for %s@%s", ctx.RequestID, module, version)
			return statusCode, headers, body, nil
		}

		h.mu.Lock()
		h.publishTimes[goModuleVersionKey(module, version)] = info.Time
		h.mu.Unlock()

		return statusCode, headers, body, nil
	}

	return &proxy.InterceptorResponse{
		Action:           proxy.ActionModifyResponse,
		ResponseModifier: modifier,
	}, nil
}

// CheckZipDownload blocks the module zip when its publish time is within the
// cooldown window. handled=false lets the request continue to malware
// analysis. An unknown publish time (go served .info from its local cache so
// the proxy never saw it) fails open for cooldown only — malware analysis
// still runs.
func (h *goCooldownHandler) CheckZipDownload(ctx *proxy.RequestContext, module, version string, cooldownDays int) (*proxy.InterceptorResponse, bool) {
	skip := pmgconfig.CooldownSkip(packagev1.Ecosystem_ECOSYSTEM_GO, module)
	if skip.SkipAll || pmgconfig.IsTrustedPackageRef(packagev1.Ecosystem_ECOSYSTEM_GO, module, version) {
		return nil, false
	}

	h.mu.Lock()
	publishTime, ok := h.publishTimes[goModuleVersionKey(module, version)]
	h.mu.Unlock()

	if !ok {
		log.Warnf("[%s] Cooldown: no publish time observed for %s@%s; cooldown not enforced for this download", ctx.RequestID, module, version)
		return nil, false
	}

	within, daysAgo, daysLeft := cooldownIsWithinWindow(publishTime, cooldownDays)
	if !within {
		return nil, false
	}

	if skip.ExemptsVersion(version) {
		auditCooldownSkips(ctx.RequestID, packagev1.Ecosystem_ECOSYSTEM_GO, module, cooldownExemptions{skipListed: []string{version}})
		return nil, false
	}

	log.Infof("[%s] Cooldown: blocking %s@%s published %d day(s) ago (%d day cooldown, %d remaining)",
		ctx.RequestID, module, version, daysAgo, cooldownDays, daysLeft)

	if h.statsCollector != nil {
		h.statsCollector.RecordCooldownBlocked(module, version, publishTime, daysAgo, daysLeft, cooldownDays)
	}

	pv := &packagev1.PackageVersion{}
	pv.SetPackage(&packagev1.Package{})
	pv.GetPackage().SetName(module)
	pv.GetPackage().SetEcosystem(packagev1.Ecosystem_ECOSYSTEM_GO)
	pv.SetVersion(version)
	audit.LogDependencyCooldown(pv, publishTime, cooldownDays, daysAgo, daysLeft)

	message := fmt.Sprintf("Package blocked by dependency cooldown: GO/%s@%s\n\nPublished %d day(s) ago; cooldown window is %d day(s) (%d remaining).",
		module, version, daysAgo, cooldownDays, daysLeft)

	return &proxy.InterceptorResponse{
		Action:       proxy.ActionBlock,
		BlockCode:    http.StatusForbidden,
		BlockMessage: message,
	}, true
}
