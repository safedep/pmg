package interceptors

import (
	"encoding/json"
	"fmt"
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

// HandleMetadataRequest is a stub — implemented in Task 4.
func (h *pypiCooldownHandler) HandleMetadataRequest(ctx *proxy.RequestContext, packageName string, cooldownDays int) (*proxy.InterceptorResponse, error) {
	return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
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

// parsePEP691UploadTime parses the ISO 8601 upload-time field from PEP 691 responses.
// Example: "2023-05-22T15:12:44.000000+00:00"
func parsePEP691UploadTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}
