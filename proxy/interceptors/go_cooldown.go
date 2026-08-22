package interceptors

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/proxy"
	gomodule "golang.org/x/mod/module"
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
	forceUncompressedNonConditionalResponse(ctx.Headers)

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
// cooldown window. When the publish time was not observed on the wire (go
// served .info from its local module cache, common on machines that used go
// before PMG), it is fetched out-of-band from the upstream proxy.
func (h *goCooldownHandler) CheckZipDownload(ctx *proxy.RequestContext, baseURL, module, version string, cooldownDays int) (*proxy.InterceptorResponse, bool) {
	return cooldownCheckDownload(ctx, packagev1.Ecosystem_ECOSYSTEM_GO, module, version, cooldownDays, h.statsCollector,
		func() (time.Time, bool) {
			h.mu.Lock()
			publishTime, ok := h.publishTimes[goModuleVersionKey(module, version)]
			h.mu.Unlock()
			if ok {
				return publishTime, true
			}
			return h.fetchPublishTime(ctx, baseURL, module, version)
		})
}

// fetchPublishTime performs a one-shot authoritative $base/$module/@v/$version.info
// fetch and caches the result. Best-effort: any failure means no publish time.
func (h *goCooldownHandler) fetchPublishTime(ctx *proxy.RequestContext, baseURL, module, version string) (time.Time, bool) {
	if baseURL == "" {
		return time.Time{}, false
	}

	escapedPath, err := gomodule.EscapePath(module)
	if err != nil {
		return time.Time{}, false
	}

	escapedVersion, err := gomodule.EscapeVersion(version)
	if err != nil {
		return time.Time{}, false
	}

	infoURL := fmt.Sprintf("%s/%s/@v/%s.info", strings.TrimSuffix(baseURL, "/"), escapedPath, escapedVersion)

	resp, err := cooldownFetchClient.Get(infoURL)
	if err != nil {
		log.Warnf("[%s] Cooldown: failed to fetch %s: %v", ctx.RequestID, infoURL, err)
		return time.Time{}, false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		log.Warnf("[%s] Cooldown: fetching %s returned HTTP %d", ctx.RequestID, infoURL, resp.StatusCode)
		return time.Time{}, false
	}

	var info struct {
		Time time.Time `json:"Time"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil || info.Time.IsZero() {
		log.Warnf("[%s] Cooldown: failed to parse publish time from %s", ctx.RequestID, infoURL)
		return time.Time{}, false
	}

	h.mu.Lock()
	h.publishTimes[goModuleVersionKey(module, version)] = info.Time
	h.mu.Unlock()

	return info.Time, true
}
