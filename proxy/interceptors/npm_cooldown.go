package interceptors

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
)

// npmMetadataTimeSkipKeys are non-version keys present in the NPM metadata "time" object.
var npmMetadataTimeSkipKeys = map[string]bool{
	"created":  true,
	"modified": true,
}

// NpmCooldownHandler handles dependency cooldown for npm packages.
// It strips recently-published versions from metadata responses so npm's
// resolver naturally falls back to the latest eligible version.
type NpmCooldownHandler struct {
	statsCollector *AnalysisStatsCollector
}

// NewNpmCooldownHandler creates a new cooldown handler.
func NewNpmCooldownHandler(statsCollector *AnalysisStatsCollector) *NpmCooldownHandler {
	return &NpmCooldownHandler{
		statsCollector: statsCollector,
	}
}

// HandleMetadataRequest overrides the Accept header to force the registry to return
// a full packument (which includes publish dates in the "time" field), then registers
// a response modifier that strips versions within the cooldown window.
func (h *NpmCooldownHandler) HandleMetadataRequest(ctx *proxy.RequestContext, packageName string) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Cooldown: registering metadata modifier for %s", ctx.RequestID, packageName)

	// Force full packument so the response always contains the "time" field.
	// Abbreviated metadata (Accept: application/vnd.npm.install-v1+json) omits it.
	ctx.Headers.Set("Accept", "application/json")

	modifier := func(statusCode int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		dates, err := parseNpmMetadataTime(body)
		if err != nil {
			log.Warnf("[%s] Cooldown: failed to parse metadata time for %s: %v", ctx.RequestID, packageName, err)
			return statusCode, headers, body, nil
		}

		log.Debugf("[%s] Cooldown: parsed %d publish dates for %s", ctx.RequestID, len(dates), packageName)

		cooldownDays := config.Get().Config.DependencyCooldown.Days
		strippedBody, stripped, remaining := stripCooldownVersions(body, dates, cooldownDays)
		if stripped > 0 {
			log.Infof("[%s] Cooldown: stripped %d version(s) from %s metadata (%d days, %d eligible remain)",
				ctx.RequestID, stripped, packageName, cooldownDays, remaining)

			if remaining == 0 && h.statsCollector != nil {
				latestStripped, latestDate := oldestVersion(dates)
				if latestStripped != "" {
					cooldownDuration := time.Duration(cooldownDays) * 24 * time.Hour
					age := time.Since(latestDate)
					daysAgo := int(age.Hours() / 24)
					daysLeft := int(math.Ceil((cooldownDuration - age).Hours() / 24))
					h.statsCollector.RecordCooldownBlocked(packageName, latestStripped, latestDate, daysAgo, daysLeft, cooldownDays)
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

// parseNpmMetadataTime extracts version publish dates from an NPM package metadata body.
func parseNpmMetadataTime(body []byte) (map[string]time.Time, error) {
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
func stripCooldownVersions(body []byte, dates map[string]time.Time, cooldownDays int) ([]byte, int, int) {
	cooldownDuration := time.Duration(cooldownDays) * 24 * time.Hour
	now := time.Now()

	tooNew := make(map[string]bool)
	for version, publishDate := range dates {
		if now.Sub(publishDate) < cooldownDuration {
			tooNew[version] = true
		}
	}

	remaining := len(dates) - len(tooNew)

	if len(tooNew) == 0 {
		return body, 0, remaining
	}

	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(body, &metadata); err != nil {
		return body, 0, remaining
	}

	if raw, ok := metadata["versions"]; ok {
		var versions map[string]json.RawMessage
		if err := json.Unmarshal(raw, &versions); err == nil {
			for v := range tooNew {
				delete(versions, v)
			}
			if updated, err := json.Marshal(versions); err == nil {
				metadata["versions"] = updated
			}
		}
	}

	if raw, ok := metadata["time"]; ok {
		var timeMap map[string]string
		if err := json.Unmarshal(raw, &timeMap); err == nil {
			for v := range tooNew {
				delete(timeMap, v)
			}
			if updated, err := json.Marshal(timeMap); err == nil {
				metadata["time"] = updated
			}
		}
	}

	if raw, ok := metadata["dist-tags"]; ok {
		var distTags map[string]string
		if err := json.Unmarshal(raw, &distTags); err == nil {
			changed := false
			for tag, version := range distTags {
				if tooNew[version] {
					latest := latestNonCooldownVersion(dates, tooNew)
					if latest != "" {
						distTags[tag] = latest
					} else {
						delete(distTags, tag)
					}
					changed = true
				}
			}
			if changed {
				if updated, err := json.Marshal(distTags); err == nil {
					metadata["dist-tags"] = updated
				}
			}
		}
	}

	result, err := json.Marshal(metadata)
	if err != nil {
		return body, 0, remaining
	}

	return result, len(tooNew), remaining
}

// oldestVersion returns the version with the earliest publish date.
// When all versions are blocked by cooldown, this is the version closest
// to exiting the cooldown window (shortest wait for the user).
func oldestVersion(dates map[string]time.Time) (string, time.Time) {
	var oldest string
	var oldestTime time.Time

	for version, publishDate := range dates {
		if oldestTime.IsZero() || publishDate.Before(oldestTime) {
			oldest = version
			oldestTime = publishDate
		}
	}

	return oldest, oldestTime
}

func latestNonCooldownVersion(dates map[string]time.Time, tooNew map[string]bool) string {
	var latest string
	var latestTime time.Time

	for version, publishDate := range dates {
		if tooNew[version] {
			continue
		}
		if publishDate.After(latestTime) {
			latest = version
			latestTime = publishDate
		}
	}

	return latest
}
