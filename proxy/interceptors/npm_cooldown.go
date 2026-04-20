package interceptors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/proxy"
)

// npmMetadataTimeSkipKeys are non-version keys present in the NPM metadata "time" object.
var npmMetadataTimeSkipKeys = map[string]bool{
	"created":  true,
	"modified": true,
}

// npmCooldownHandler handles dependency cooldown for npm packages.
// It strips recently-published versions from metadata responses so npm's
// resolver naturally falls back to the latest eligible version.
type npmCooldownHandler struct {
	statsCollector *AnalysisStatsCollector
}

func newNpmCooldownHandler(statsCollector *AnalysisStatsCollector) *npmCooldownHandler {
	return &npmCooldownHandler{
		statsCollector: statsCollector,
	}
}

// HandleMetadataRequest overrides the Accept header to force the registry to return
// a full packument (which includes publish dates in the "time" field), then registers
// a response modifier that strips versions within the cooldown window.
func (h *npmCooldownHandler) HandleMetadataRequest(ctx *proxy.RequestContext, packageName string, cooldownDays int) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Cooldown: registering metadata modifier for %s", ctx.RequestID, packageName)

	// Force full packument so the response always contains the "time" field.
	// Abbreviated metadata (Accept: application/vnd.npm.install-v1+json) omits it.
	ctx.Headers.Set("Accept", "application/json")

	// Prevent the server from compressing the response so we can parse the JSON body.
	// Go's http.Transport only auto-decompresses when it added the Accept-Encoding
	// header itself; since the client's original header is forwarded by the proxy,
	// we'd get raw gzip bytes that fail JSON parsing.
	ctx.Headers.Set("Accept-Encoding", "identity")

	// Strip conditional-GET headers so the registry cannot return 304 Not Modified.
	// A 304 has no body — the modifier would receive an empty body, fail to parse
	// it as JSON, and fail-open, letting the client use its cached (unfiltered)
	// response. Removing these forces a full 200 response on every request.
	ctx.Headers.Del("If-None-Match")
	ctx.Headers.Del("If-Modified-Since")

	modifier := func(statusCode int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		dates, err := h.parseMetadataTime(body)
		if err != nil {
			log.Warnf("[%s] Cooldown: failed to parse metadata time for %s: %v", ctx.RequestID, packageName, err)
			return statusCode, headers, body, nil
		}

		log.Debugf("[%s] Cooldown: parsed %d publish dates for %s", ctx.RequestID, len(dates), packageName)

		strippedBody, stripped, remaining := h.stripCooldownVersions(body, dates, cooldownDays)
		if stripped > 0 {
			log.Infof("[%s] Cooldown: stripped %d version(s) from %s metadata (%d days, %d eligible remain)",
				ctx.RequestID, stripped, packageName, cooldownDays, remaining)

			if remaining == 0 && h.statsCollector != nil {
				oldestVer, oldestDate := cooldownOldestVersion(dates)
				if oldestVer != "" {
					_, daysAgo, daysLeft := cooldownIsWithinWindow(oldestDate, cooldownDays)
					h.statsCollector.RecordCooldownBlocked(packageName, oldestVer, oldestDate, daysAgo, daysLeft, cooldownDays)
				}
			}

			// Prevent npm from caching the modified response. Without this,
			// npm would serve the stripped metadata from cache even after the
			// cooldown window passes or settings change.
			headers.Set("Cache-Control", "no-store")

			return statusCode, headers, strippedBody, nil
		}

		return statusCode, headers, body, nil
	}

	return &proxy.InterceptorResponse{
		Action:           proxy.ActionModifyResponse,
		ResponseModifier: modifier,
	}, nil
}

// parseMetadataTime extracts version publish dates from an NPM package metadata body.
func (h *npmCooldownHandler) parseMetadataTime(body []byte) (map[string]time.Time, error) {
	var metadata struct {
		Time map[string]string `json:"time"`
	}

	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal npm metadata: %w", err)
	}

	if metadata.Time == nil {
		return map[string]time.Time{}, nil
	}

	dates := make(map[string]time.Time, len(metadata.Time))
	for version, dateStr := range metadata.Time {
		if npmMetadataTimeSkipKeys[version] {
			continue
		}

		t, err := time.Parse(time.RFC3339, dateStr)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05.000Z", dateStr)
			if err != nil {
				log.Debugf("Skipping unparseable publish date for version %s: %q", version, dateStr)
				continue
			}
		}

		dates[version] = t
	}

	return dates, nil
}

// stripCooldownVersions removes versions published within the cooldown window from the
// NPM metadata response. It strips entries from "versions", "time", and updates "dist-tags".
func (h *npmCooldownHandler) stripCooldownVersions(body []byte, dates map[string]time.Time, cooldownDays int) ([]byte, int, int) {
	tooNew := make(map[string]bool)
	for version, publishDate := range dates {
		if withinCooldown, _, _ := cooldownIsWithinWindow(publishDate, cooldownDays); withinCooldown {
			tooNew[version] = true
		}
	}

	remaining := len(dates) - len(tooNew)

	if len(tooNew) == 0 {
		return body, 0, remaining
	}

	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(body, &metadata); err != nil {
		log.Warnf("Cooldown: failed to unmarshal metadata body: %v", err)
		return body, 0, remaining
	}

	if raw, ok := metadata["versions"]; ok {
		var versions map[string]json.RawMessage
		if err := json.Unmarshal(raw, &versions); err != nil {
			log.Warnf("Cooldown: failed to unmarshal versions field: %v", err)
		} else {
			for v := range tooNew {
				delete(versions, v)
			}
			if updated, err := json.Marshal(versions); err != nil {
				log.Warnf("Cooldown: failed to marshal updated versions: %v", err)
			} else {
				metadata["versions"] = updated
			}
		}
	}

	if raw, ok := metadata["time"]; ok {
		var timeMap map[string]string
		if err := json.Unmarshal(raw, &timeMap); err != nil {
			log.Warnf("Cooldown: failed to unmarshal time field: %v", err)
		} else {
			for v := range tooNew {
				delete(timeMap, v)
			}
			if updated, err := json.Marshal(timeMap); err != nil {
				log.Warnf("Cooldown: failed to marshal updated time: %v", err)
			} else {
				metadata["time"] = updated
			}
		}
	}

	if raw, ok := metadata["dist-tags"]; ok {
		var distTags map[string]string
		if err := json.Unmarshal(raw, &distTags); err != nil {
			log.Warnf("Cooldown: failed to unmarshal dist-tags field: %v", err)
		} else {
			changed := false
			for tag, version := range distTags {
				if tooNew[version] {
					latest := cooldownLatestEligibleVersion(dates, tooNew)
					if latest != "" {
						distTags[tag] = latest
					} else {
						delete(distTags, tag)
					}
					changed = true
				}
			}
			if changed {
				if updated, err := json.Marshal(distTags); err != nil {
					log.Warnf("Cooldown: failed to marshal updated dist-tags: %v", err)
				} else {
					metadata["dist-tags"] = updated
				}
			}
		}
	}

	result, err := json.Marshal(metadata)
	if err != nil {
		log.Warnf("Cooldown: failed to marshal final metadata: %v", err)
		return body, 0, remaining
	}

	return result, len(tooNew), remaining
}

