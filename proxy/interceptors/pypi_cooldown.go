package interceptors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/proxy"
)

const pypiSimpleAPIContentType = "application/vnd.pypi.simple.v1+json"

// pypiCooldownHandler handles dependency cooldown for PyPI packages.
// It strips recently-published file entries from PEP 691 Simple API responses
// so pip's resolver naturally falls back to the latest eligible version.
type pypiCooldownHandler struct {
	statsCollector *AnalysisStatsCollector
}

func newPypiCooldownHandler(statsCollector *AnalysisStatsCollector) *pypiCooldownHandler {
	return &pypiCooldownHandler{statsCollector: statsCollector}
}

// HandleMetadataRequest overrides the Accept header to force a PEP 691 JSON response,
// then registers a response modifier that strips files for versions within the cooldown window.
func (h *pypiCooldownHandler) HandleMetadataRequest(ctx *proxy.RequestContext, packageName string, cooldownDays int, pinnedVersion string) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Cooldown: registering metadata modifier for %s", ctx.RequestID, packageName)

	// Force PEP 691 JSON so we receive upload-time per file entry.
	ctx.Headers.Set("Accept", pypiSimpleAPIContentType)
	// Prevent compression so the response body can be parsed as JSON directly.
	ctx.Headers.Set("Accept-Encoding", "identity")
	// Strip conditional-GET headers so PyPI cannot return 304 Not Modified.
	// A 304 has no body — the modifier would receive an empty body, fail to parse
	// it as JSON, and fail-open, letting the client use its cached (unfiltered)
	// response. Removing these forces a full 200 response on every request.
	ctx.Headers.Del("If-None-Match")
	ctx.Headers.Del("If-Modified-Since")

	modifier := func(statusCode int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		dates, err := h.parsePEP691Files(body)
		if err != nil {
			log.Warnf("[%s] Cooldown: failed to parse PEP 691 metadata for %s: %v", ctx.RequestID, packageName, err)
			return statusCode, headers, body, nil
		}

		log.Debugf("[%s] Cooldown: parsed %d versions for %s", ctx.RequestID, len(dates), packageName)

		strippedBody, stripped, remaining := h.stripCooldownFiles(body, dates, cooldownDays)
		if stripped > 0 {
			log.Infof("[%s] Cooldown: stripped %d version(s) from %s metadata (%d days, %d eligible remain)",
				ctx.RequestID, stripped, packageName, cooldownDays, remaining)

			if h.statsCollector != nil {
				if remaining == 0 {
					oldestVer, oldestDate := cooldownOldestVersion(dates)
					if oldestVer != "" {
						_, daysAgo, daysLeft := cooldownIsWithinWindow(oldestDate, cooldownDays)
						h.statsCollector.RecordCooldownBlocked(packageName, oldestVer, oldestDate, daysAgo, daysLeft, cooldownDays)
					}
				} else if pinnedVersion != "" {
					if pinnedDate, ok := dates[pinnedVersion]; ok {
						if withinCooldown, daysAgo, daysLeft := cooldownIsWithinWindow(pinnedDate, cooldownDays); withinCooldown {
							h.statsCollector.RecordCooldownBlocked(packageName, pinnedVersion, pinnedDate, daysAgo, daysLeft, cooldownDays)
						}
					}
				}
			}

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

// parsePEP691Files extracts the earliest upload-time per version from a PEP 691 JSON body.
// Files with missing or unparseable upload-time are skipped (treated as eligible).
// Multiple files for the same version (sdist + wheels) use the earliest upload-time.
func (h *pypiCooldownHandler) parsePEP691Files(body []byte) (map[string]time.Time, error) {
	var resp struct {
		Files []struct {
			Filename   string `json:"filename"`
			UploadTime string `json:"upload-time"`
		} `json:"files"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PEP 691 response: %w", err)
	}

	dates := make(map[string]time.Time)
	for _, f := range resp.Files {
		if f.UploadTime == "" {
			log.Debugf("Cooldown: skipping file %s with missing upload-time", f.Filename)
			continue
		}

		t, err := parsePEP691UploadTime(f.UploadTime)
		if err != nil {
			log.Debugf("Cooldown: skipping file %s with unparseable upload-time %q: %v", f.Filename, f.UploadTime, err)
			continue
		}

		pkgInfo, err := parseFilename(f.Filename)
		if err != nil {
			log.Debugf("Cooldown: skipping file %s with unparseable filename: %v", f.Filename, err)
			continue
		}

		version := pkgInfo.GetVersion()
		if version == "" {
			continue
		}

		// Use the earliest upload-time across all files for a given version
		if existing, ok := dates[version]; !ok || t.Before(existing) {
			dates[version] = t
		}
	}

	return dates, nil
}

// stripCooldownFiles removes all file entries for versions within the cooldown window
// from a PEP 691 JSON body. Returns the modified body, number of versions stripped,
// and number of versions remaining.
func (h *pypiCooldownHandler) stripCooldownFiles(body []byte, dates map[string]time.Time, cooldownDays int) ([]byte, int, int) {
	tooNew := make(map[string]bool)
	for version, uploadDate := range dates {
		if within, _, _ := cooldownIsWithinWindow(uploadDate, cooldownDays); within {
			tooNew[version] = true
		}
	}

	remaining := len(dates) - len(tooNew)

	if len(tooNew) == 0 {
		return body, 0, remaining
	}

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Warnf("Cooldown: failed to unmarshal PEP 691 body for stripping: %v", err)
		return body, 0, remaining
	}

	rawFiles, ok := resp["files"]
	if !ok {
		return body, 0, remaining
	}

	var files []json.RawMessage
	if err := json.Unmarshal(rawFiles, &files); err != nil {
		log.Warnf("Cooldown: failed to unmarshal files array: %v", err)
		return body, 0, remaining
	}

	filtered := make([]json.RawMessage, 0, len(files))
	for _, rawFile := range files {
		var f struct {
			Filename string `json:"filename"`
		}
		if err := json.Unmarshal(rawFile, &f); err != nil {
			// Keep files we cannot parse to avoid accidentally dropping valid entries
			filtered = append(filtered, rawFile)
			continue
		}

		pkgInfo, err := parseFilename(f.Filename)
		if err != nil {
			// unparseable filename — keep it (fail-open)
			filtered = append(filtered, rawFile)
			continue
		}
		if tooNew[pkgInfo.GetVersion()] {
			continue // strip
		}
		filtered = append(filtered, rawFile)
	}

	updatedFiles, err := json.Marshal(filtered)
	if err != nil {
		log.Warnf("Cooldown: failed to marshal filtered files array: %v", err)
		return body, 0, remaining
	}
	resp["files"] = updatedFiles

	result, err := json.Marshal(resp)
	if err != nil {
		log.Warnf("Cooldown: failed to marshal final PEP 691 response: %v", err)
		return body, 0, remaining
	}

	return result, len(tooNew), remaining
}

// parsePEP691UploadTime parses the ISO 8601 upload-time field from PEP 691 responses.
// Example: "2023-05-22T15:12:44.000000+00:00"
func parsePEP691UploadTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}
