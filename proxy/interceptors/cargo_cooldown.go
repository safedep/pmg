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

// cargoIndexEntry is one sparse-index NDJSON line. vers is empty for
// unparseable lines, which are kept verbatim (fail open).
type cargoIndexEntry struct {
	raw  []byte
	vers string
}

// HandleIndexRequest registers a response modifier that captures per-version
// publish times for the download check and strips versions within the
// cooldown window. Skip-list semantics are handled here so callers do not
// need to consult the config.
func (h *cargoCooldownHandler) HandleIndexRequest(ctx *proxy.RequestContext, crate string, cooldownDays int, pinnedVersion string) (*proxy.InterceptorResponse, error) {
	skip := pmgconfig.CooldownSkip(packagev1.Ecosystem_ECOSYSTEM_CARGO, crate)

	forceUncompressedNonConditionalResponse(ctx.Headers)

	modifier := func(statusCode int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		if statusCode != http.StatusOK {
			return statusCode, headers, body, nil
		}

		entries, dates := parseCargoIndexBody(ctx.RequestID, crate, body)
		h.recordPublishTimes(crate, dates)

		if skip.SkipAll {
			// Whole crate is on the cooldown skip list: pass the index through
			// unmodified. The .crate download still hits analyzePackage, so
			// malware analysis is preserved.
			return statusCode, headers, body, nil
		}

		exempt := cooldownExemptVersions(packagev1.Ecosystem_ECOSYSTEM_CARGO, crate, skip, dates, cooldownDays)
		auditCooldownSkips(ctx.RequestID, packagev1.Ecosystem_ECOSYSTEM_CARGO, crate, exempt)

		strippedBody, stripped, remaining := stripCargoIndexLines(entries, dates, cooldownDays, exempt.all)
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

// parseCargoIndexBody splits a sparse-index body into NDJSON entries and the
// publish dates parsed from them. Unparseable lines get an empty vers and no
// date (fail open). pubtime is optional in the index format; versions without
// it cannot be stripped, and malware analysis still runs at download time.
func parseCargoIndexBody(requestID, crate string, body []byte) ([]cargoIndexEntry, map[string]time.Time) {
	var entries []cargoIndexEntry
	dates := map[string]time.Time{}

	for _, raw := range bytes.Split(body, []byte("\n")) {
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}

		var line struct {
			Vers    string     `json:"vers"`
			PubTime *time.Time `json:"pubtime"`
		}
		if err := json.Unmarshal(raw, &line); err != nil || line.Vers == "" {
			log.Debugf("[%s] Cooldown: keeping unparseable index line for %s", requestID, crate)
			entries = append(entries, cargoIndexEntry{raw: raw})
			continue
		}

		entries = append(entries, cargoIndexEntry{raw: raw, vers: line.Vers})
		if line.PubTime != nil && !line.PubTime.IsZero() {
			dates[line.Vers] = *line.PubTime
		}
	}

	return entries, dates
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

// stripCargoIndexLines removes entries whose version is within the cooldown
// window. Surviving entries keep their original bytes so checksums and fields
// PMG does not model pass through untouched. remaining counts every surviving
// entry, including versions without a pubtime, so a strip that leaves
// installable versions is never reported as a definite block. Returns a nil
// body when nothing is stripped; callers keep the original.
func stripCargoIndexLines(entries []cargoIndexEntry, dates map[string]time.Time, cooldownDays int, exemptVersions map[string]bool) ([]byte, []string, int) {
	tooNew := map[string]bool{}
	for version, publishDate := range dates {
		if exemptVersions[version] {
			continue
		}
		if within, _, _ := cooldownIsWithinWindow(publishDate, cooldownDays); within {
			tooNew[version] = true
		}
	}

	if len(tooNew) == 0 {
		return nil, nil, len(entries)
	}

	var kept [][]byte
	var stripped []string
	for _, entry := range entries {
		if entry.vers != "" && tooNew[entry.vers] {
			stripped = append(stripped, entry.vers)
			continue
		}
		kept = append(kept, entry.raw)
	}

	body := bytes.Join(kept, []byte("\n"))
	if len(kept) > 0 {
		body = append(body, '\n')
	}

	return body, stripped, len(kept)
}

// CheckCrateDownload blocks a .crate download when its publish time is within
// the cooldown window. When the publish time was not observed on the wire
// (cargo resolved from Cargo.lock or a warm index cache), it is fetched
// out-of-band from the upstream sparse index.
func (h *cargoCooldownHandler) CheckCrateDownload(ctx *proxy.RequestContext, crate, version string, cooldownDays int) (*proxy.InterceptorResponse, bool) {
	return cooldownCheckDownload(ctx, packagev1.Ecosystem_ECOSYSTEM_CARGO, crate, version, cooldownDays, h.statsCollector,
		func() (time.Time, bool) {
			h.mu.Lock()
			publishTime, ok := h.publishTimes[cargoCrateVersionKey(crate, version)]
			h.mu.Unlock()
			if ok {
				return publishTime, true
			}
			return h.fetchPublishTime(ctx, crate, version)
		})
}

// fetchPublishTime performs a one-shot authoritative sparse-index fetch for
// the crate and caches every version's publish time from it. Best-effort: any
// failure means no publish time.
func (h *cargoCooldownHandler) fetchPublishTime(ctx *proxy.RequestContext, crate, version string) (time.Time, bool) {
	indexURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(h.indexBaseURL, "/"), cargoSparseIndexPath(crate))

	resp, err := cooldownFetchClient.Get(indexURL)
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

	_, dates := parseCargoIndexBody(ctx.RequestID, crate, body)
	h.recordPublishTimes(crate, dates)

	publishTime, ok := dates[version]
	return publishTime, ok
}
