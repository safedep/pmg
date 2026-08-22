package interceptors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/proxy"
)

// cargoCooldownHandler enforces dependency cooldown for crates. The sparse
// index carries a pubtime per version, so in-window versions are stripped from
// index responses (like npm metadata stripping) and cargo's resolver falls
// back to an older release. Stripping alone is not enough: a Cargo.lock build
// downloads .crate files without touching the index, so downloads are also
// checked against publish times captured from index responses, with an
// out-of-band index fetch as fallback (like the Go handler).
type cargoCooldownHandler struct {
	statsCollector *AnalysisStatsCollector
	indexBaseURL   string

	mu           sync.Mutex
	publishTimes map[string]time.Time
}

const defaultCargoIndexBaseURL = "https://index.crates.io"

func newCargoCooldownHandler(statsCollector *AnalysisStatsCollector, indexBaseURL string) *cargoCooldownHandler {
	if indexBaseURL == "" {
		indexBaseURL = defaultCargoIndexBaseURL
	}

	return &cargoCooldownHandler{
		statsCollector: statsCollector,
		indexBaseURL:   indexBaseURL,
		publishTimes:   map[string]time.Time{},
	}
}

// cargoCrateVersionKey keys publish times by lowercased crate name: index
// paths are lowercase while download URLs use the crate's canonical case.
func cargoCrateVersionKey(name, version string) string {
	return strings.ToLower(name) + "@" + version
}

// cargoIndexLine is the subset of a sparse-index NDJSON line the cooldown
// needs. pubtime is optional in the index format; versions without it cannot
// be stripped (fail open, malware analysis still runs at download time).
type cargoIndexLine struct {
	Name    string     `json:"name"`
	Vers    string     `json:"vers"`
	PubTime *time.Time `json:"pubtime"`
}

// HandleIndexRequest registers a response modifier that captures per-version
// publish times for the download check and strips versions within the
// cooldown window. Skip-list semantics are handled here so callers do not
// need to consult the config.
func (h *cargoCooldownHandler) HandleIndexRequest(ctx *proxy.RequestContext, crate string, cooldownDays int, pinnedVersion string) (*proxy.InterceptorResponse, error) {
	skip := pmgconfig.CooldownSkip(packagev1.Ecosystem_ECOSYSTEM_CARGO, crate)

	// Force an uncompressed, non-conditional response so the body is parseable
	// NDJSON rather than raw gzip bytes or an empty 304 (same as the npm
	// metadata modifier).
	ctx.Headers.Set("Accept-Encoding", "identity")
	ctx.Headers.Del("If-None-Match")
	ctx.Headers.Del("If-Modified-Since")

	modifier := func(statusCode int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		if statusCode != http.StatusOK {
			return statusCode, headers, body, nil
		}

		lines, dates := h.parseIndexBody(ctx.RequestID, crate, body)
		h.recordPublishTimes(crate, dates)

		if skip.SkipAll {
			// Whole crate is on the cooldown skip list: pass the index through
			// unmodified. The .crate download still hits analyzePackage, so
			// malware analysis is preserved.
			return statusCode, headers, body, nil
		}

		exempt := cooldownExemptVersions(packagev1.Ecosystem_ECOSYSTEM_CARGO, crate, skip, dates, cooldownDays)
		auditCooldownSkips(ctx.RequestID, packagev1.Ecosystem_ECOSYSTEM_CARGO, crate, exempt)

		strippedBody, stripped, remaining := stripCargoIndexLines(lines, dates, cooldownDays, exempt.all)
		if len(stripped) == 0 {
			return statusCode, headers, body, nil
		}

		log.Infof("[%s] Cooldown: stripped %d version(s) from %s index (%d days, %d eligible remain)",
			ctx.RequestID, len(stripped), crate, cooldownDays, remaining)

		recordCooldownStats(h.statsCollector, packagev1.Ecosystem_ECOSYSTEM_CARGO, crate, pinnedVersion, dates, stripped, remaining, cooldownDays)

		// Without validators cargo cannot revalidate the filtered body later
		// with a conditional request, and no-store keeps it from serving the
		// filtered index from cache after the window passes.
		headers.Set("Cache-Control", "no-store")
		headers.Del("ETag")
		headers.Del("Last-Modified")

		return statusCode, headers, strippedBody, nil
	}

	return &proxy.InterceptorResponse{
		Action:           proxy.ActionModifyResponse,
		ResponseModifier: modifier,
	}, nil
}

// parseIndexBody splits a sparse-index body into raw NDJSON lines and the
// publish dates parsed from them. Unparseable lines survive verbatim with no
// date (fail open).
func (h *cargoCooldownHandler) parseIndexBody(requestID, crate string, body []byte) ([][]byte, map[string]time.Time) {
	rawLines := bytes.Split(body, []byte("\n"))
	dates := map[string]time.Time{}

	for _, raw := range rawLines {
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}

		var line cargoIndexLine
		if err := json.Unmarshal(raw, &line); err != nil || line.Vers == "" {
			log.Debugf("[%s] Cooldown: skipping unparseable index line for %s", requestID, crate)
			continue
		}

		if line.PubTime != nil && !line.PubTime.IsZero() {
			dates[line.Vers] = *line.PubTime
		}
	}

	return rawLines, dates
}

// recordPublishTimes caches a crate's per-version publish times for the
// upcoming .crate download checks.
func (h *cargoCooldownHandler) recordPublishTimes(crate string, dates map[string]time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for version, t := range dates {
		h.publishTimes[cargoCrateVersionKey(crate, version)] = t
	}
}

// stripCargoIndexLines removes lines whose version is within the cooldown
// window. Surviving lines keep their original bytes so checksums and fields
// PMG does not model pass through untouched.
func stripCargoIndexLines(rawLines [][]byte, dates map[string]time.Time, cooldownDays int, exemptVersions map[string]bool) ([]byte, []string, int) {
	tooNew := map[string]bool{}
	for version, publishDate := range dates {
		if exemptVersions[version] {
			continue
		}
		if within, _, _ := cooldownIsWithinWindow(publishDate, cooldownDays); within {
			tooNew[version] = true
		}
	}

	remaining := len(dates) - len(tooNew)
	if len(tooNew) == 0 {
		return bytes.Join(rawLines, []byte("\n")), nil, remaining
	}

	var kept [][]byte
	var stripped []string
	for _, raw := range rawLines {
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}

		var line cargoIndexLine
		if err := json.Unmarshal(raw, &line); err == nil && tooNew[line.Vers] {
			stripped = append(stripped, line.Vers)
			continue
		}

		kept = append(kept, raw)
	}

	body := bytes.Join(kept, []byte("\n"))
	if len(kept) > 0 {
		body = append(body, '\n')
	}

	return body, stripped, remaining
}

// CheckCrateDownload blocks a .crate download when its publish time is within
// the cooldown window. handled=false lets the request continue to malware
// analysis. When the publish time was not observed on the wire (cargo resolved
// from Cargo.lock or a warm index cache), it is fetched out-of-band from the
// upstream sparse index; only if that also fails does cooldown fail open —
// malware analysis still runs.
func (h *cargoCooldownHandler) CheckCrateDownload(ctx *proxy.RequestContext, crate, version string, cooldownDays int) (*proxy.InterceptorResponse, bool) {
	skip := pmgconfig.CooldownSkip(packagev1.Ecosystem_ECOSYSTEM_CARGO, crate)
	if skip.SkipAll || pmgconfig.IsTrustedPackageRef(packagev1.Ecosystem_ECOSYSTEM_CARGO, crate, version) {
		return nil, false
	}

	key := cargoCrateVersionKey(crate, version)

	h.mu.Lock()
	publishTime, ok := h.publishTimes[key]
	h.mu.Unlock()

	if !ok {
		publishTime, ok = h.fetchPublishTime(ctx, crate, version)
	}

	if !ok {
		log.Warnf("[%s] Cooldown: no publish time available for %s@%s; cooldown not enforced for this download", ctx.RequestID, crate, version)
		return nil, false
	}

	within, daysAgo, daysLeft := cooldownIsWithinWindow(publishTime, cooldownDays)
	if !within {
		return nil, false
	}

	if skip.ExemptsVersion(version) {
		auditCooldownSkips(ctx.RequestID, packagev1.Ecosystem_ECOSYSTEM_CARGO, crate, cooldownExemptions{skipListed: []string{version}})
		return nil, false
	}

	log.Infof("[%s] Cooldown: blocking %s@%s published %d day(s) ago (%d day cooldown, %d remaining)",
		ctx.RequestID, crate, version, daysAgo, cooldownDays, daysLeft)

	if h.statsCollector != nil {
		h.statsCollector.RecordCooldownBlocked(crate, version, publishTime, daysAgo, daysLeft, cooldownDays)
	}

	pv := &packagev1.PackageVersion{}
	pv.SetPackage(&packagev1.Package{})
	pv.GetPackage().SetName(crate)
	pv.GetPackage().SetEcosystem(packagev1.Ecosystem_ECOSYSTEM_CARGO)
	pv.SetVersion(version)
	audit.LogDependencyCooldown(pv, publishTime, cooldownDays, daysAgo, daysLeft)

	return &proxy.InterceptorResponse{
		Action:      proxy.ActionBlock,
		BlockCode:   http.StatusForbidden,
		BlockReason: proxy.BlockReasonDependencyCooldown,
		BlockContext: &proxy.BlockContext{
			Ecosystem:        packagev1.Ecosystem_ECOSYSTEM_CARGO,
			PackageName:      crate,
			PackageVersion:   version,
			CooldownDays:     cooldownDays,
			CooldownDaysAgo:  daysAgo,
			CooldownDaysLeft: daysLeft,
		},
	}, true
}

// cargoIndexFetchClient fetches index files out-of-band, straight to the
// upstream sparse index rather than back through PMG's own in-process proxy
// (which would re-intercept the request). It honors the process' own proxy
// environment, not the child's injected one.
var cargoIndexFetchClient = &http.Client{Timeout: 10 * time.Second}

// fetchPublishTime performs a one-shot authoritative sparse-index fetch for
// the crate and caches every version's publish time from it. Best-effort: any
// failure means no publish time.
func (h *cargoCooldownHandler) fetchPublishTime(ctx *proxy.RequestContext, crate, version string) (time.Time, bool) {
	indexURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(h.indexBaseURL, "/"), cargoSparseIndexPath(crate))

	resp, err := cargoIndexFetchClient.Get(indexURL)
	if err != nil {
		log.Warnf("[%s] Cooldown: failed to fetch %s: %v", ctx.RequestID, indexURL, err)
		return time.Time{}, false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		log.Warnf("[%s] Cooldown: fetching %s returned HTTP %d", ctx.RequestID, indexURL, resp.StatusCode)
		return time.Time{}, false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		log.Warnf("[%s] Cooldown: failed to read %s: %v", ctx.RequestID, indexURL, err)
		return time.Time{}, false
	}

	_, dates := h.parseIndexBody(ctx.RequestID, crate, body)

	h.mu.Lock()
	for v, t := range dates {
		h.publishTimes[cargoCrateVersionKey(crate, v)] = t
	}
	publishTime, ok := h.publishTimes[cargoCrateVersionKey(crate, version)]
	h.mu.Unlock()

	return publishTime, ok
}
