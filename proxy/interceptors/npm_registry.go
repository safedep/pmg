package interceptors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
)

var npmRegistryDomains = registryConfigMap{
	"registry.npmjs.org": {
		Host:                 "registry.npmjs.org",
		SupportedForAnalysis: true,
		Parser:               npmParser{},
	},
	"registry.yarnpkg.com": {
		Host:                 "registry.yarnpkg.com",
		SupportedForAnalysis: true,
		Parser:               npmParser{},
	},
	"npm.pkg.github.com": {
		Host:                 "npm.pkg.github.com",
		SupportedForAnalysis: false, // Skip analysis for now (private packages, auth complexity)
		Parser:               npmGithubParser{},
	},
	"pkg-npm.githubusercontent.com": {
		Host:                 "pkg-npm.githubusercontent.com",
		SupportedForAnalysis: false, // Skip analysis (blob storage, redirected downloads)
		Parser:               npmGithubBlobParser{},
	},
}

// npmMetadataTimeSkipKeys are non-version keys present in the NPM metadata "time" object.
var npmMetadataTimeSkipKeys = map[string]bool{
	"created":  true,
	"modified": true,
}

// NpmRegistryInterceptor intercepts NPM registry requests and analyzes packages for malware.
// It embeds baseRegistryInterceptor to reuse ecosystem agnostic functionality.
type NpmRegistryInterceptor struct {
	baseRegistryInterceptor
}

var _ proxy.Interceptor = (*NpmRegistryInterceptor)(nil)
var _ proxy.MITMDecider = (*NpmRegistryInterceptor)(nil)

// NewNpmRegistryInterceptor creates a new NPM registry interceptor
func NewNpmRegistryInterceptor(
	analyzer analyzer.PackageVersionAnalyzer,
	cache AnalysisCache,
	statsCollector *AnalysisStatsCollector,
	confirmationChan chan *ConfirmationRequest,
) *NpmRegistryInterceptor {
	return &NpmRegistryInterceptor{
		baseRegistryInterceptor: baseRegistryInterceptor{
			analyzer:         analyzer,
			cache:            cache,
			statsCollector:   statsCollector,
			confirmationChan: confirmationChan,
		},
	}
}

// Name returns the interceptor name for logging
func (i *NpmRegistryInterceptor) Name() string {
	return "npm-registry-interceptor"
}

func (i *NpmRegistryInterceptor) ShouldMITM(ctx *proxy.RequestContext) bool {
	config := npmRegistryDomains.GetConfigForHostname(ctx.Hostname)
	if config == nil {
		return false
	}

	return config.SupportedForAnalysis
}

// ShouldIntercept determines if this interceptor should handle the given request
func (i *NpmRegistryInterceptor) ShouldIntercept(ctx *proxy.RequestContext) bool {
	return npmRegistryDomains.ContainsHostname(ctx.Hostname)
}

// HandleRequest processes the request and returns response action.
// We take a fail-open approach, allowing requests we can't parse.
func (i *NpmRegistryInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Handling NPM registry request: %s", ctx.RequestID, ctx.URL.Path)

	registryConfig := npmRegistryDomains.GetConfigForHostname(ctx.Hostname)
	if registryConfig == nil {
		log.Warnf("[%s] No registry config found for hostname: %s", ctx.RequestID, ctx.Hostname)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if !registryConfig.SupportedForAnalysis {
		log.Debugf("[%s] Skipping analysis for %s registry (not supported for analysis): %s",
			ctx.RequestID, registryConfig.Host, ctx.URL.String())
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	pkgInfo, err := registryConfig.Parser.ParseURL(ctx.URL.Path)
	if err != nil {
		log.Warnf("[%s] Failed to parse NPM registry URL %s for %s: %v",
			ctx.RequestID, ctx.URL.Path, registryConfig.Host, err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	depCooldownConfig := config.Get().Config.DependencyCooldown

	// Metadata requests: strip versions within the cooldown window so npm's resolver
	// naturally falls back to the latest eligible version.
	if !pkgInfo.IsFileDownload() {
		if depCooldownConfig.Enabled {
			return i.handleMetadataRequest(ctx, pkgInfo.GetName())
		}

		log.Debugf("[%s] Skipping analysis for metadata request: %s", ctx.RequestID, pkgInfo.GetName())
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	result, err := i.baseRegistryInterceptor.analyzePackage(
		ctx,
		packagev1.Ecosystem_ECOSYSTEM_NPM,
		pkgInfo.GetName(),
		pkgInfo.GetVersion(),
	)
	if err != nil {
		log.Errorf("[%s] Failed to analyze package %s@%s: %v", ctx.RequestID, pkgInfo.GetName(), pkgInfo.GetVersion(), err)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	return i.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, pkgInfo.GetName(), pkgInfo.GetVersion(), result)
}

// handleMetadataRequest registers a response modifier that extracts publish dates from the
// NPM metadata JSON body, caches them, and strips versions within the cooldown window.
// By removing recent versions from "versions", "time", and "dist-tags", npm's resolver
// naturally falls back to the latest eligible version — matching the behavior of npm's
// own --min-release-age flag.
func (i *NpmRegistryInterceptor) handleMetadataRequest(ctx *proxy.RequestContext, packageName string) (*proxy.InterceptorResponse, error) {
	log.Debugf("[%s] Registering metadata response modifier for %s", ctx.RequestID, packageName)

	modifier := func(statusCode int, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		dates, err := parseNpmMetadataTime(body)
		if err != nil {
			log.Warnf("[%s] Failed to parse NPM metadata time for %s: %v", ctx.RequestID, packageName, err)
			return statusCode, headers, body, nil
		}

		log.Debugf("[%s] Parsed %d publish dates for %s", ctx.RequestID, len(dates), packageName)

		cooldownDays := config.Get().Config.DependencyCooldown.Days
		strippedBody, stripped, remaining := stripCooldownVersions(body, dates, cooldownDays)
		if stripped > 0 {
			log.Infof("[%s] Stripped %d version(s) from %s metadata (cooldown: %d days, %d eligible remain)",
				ctx.RequestID, stripped, packageName, cooldownDays, remaining)

			// Only report a cooldown block when npm has no eligible version to fall back to.
			// If older versions remain, npm resolves to them silently — nothing to report.
			if remaining == 0 && i.statsCollector != nil {
				// Report the most recently published (would-have-been-latest) stripped version
				latestStripped, latestDate := mostRecentVersion(dates)
				if latestStripped != "" {
					cooldownDuration := time.Duration(cooldownDays) * 24 * time.Hour
					age := time.Since(latestDate)
					daysAgo := int(age.Hours() / 24)
					daysLeft := int((cooldownDuration-age).Hours()/24) + 1
					i.statsCollector.RecordCooldownBlocked(packageName, latestStripped, latestDate, daysAgo, daysLeft, cooldownDays)
				}
			}

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
// The NPM registry embeds a "time" object mapping version strings to RFC3339 timestamps.
// Non-version keys (created, modified) are skipped.
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
			// NPM sometimes uses millisecond precision: 2024-01-15T10:30:00.000Z
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
// NPM metadata response. It strips entries from "versions", "time", and updates "dist-tags"
// so npm's resolver naturally picks the latest eligible version.
// Returns the modified body, count of stripped versions, and count of remaining eligible versions.
// If no versions need stripping, returns the original body unchanged with counts (0, total).
func stripCooldownVersions(body []byte, dates map[string]time.Time, cooldownDays int) ([]byte, int, int) {
	cooldownDuration := time.Duration(cooldownDays) * 24 * time.Hour
	now := time.Now()

	// Identify which versions to strip
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

	// Parse into a generic map to preserve all fields we don't care about
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(body, &metadata); err != nil {
		return body, 0, remaining
	}

	// Strip from "versions"
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

	// Strip from "time"
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

	// Fix "dist-tags" — if any tag points to a stripped version, update it to the
	// latest remaining version
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

// mostRecentVersion returns the version with the most recent publish date from dates.
func mostRecentVersion(dates map[string]time.Time) (string, time.Time) {
	var latest string
	var latestTime time.Time

	for version, publishDate := range dates {
		if publishDate.After(latestTime) {
			latest = version
			latestTime = publishDate
		}
	}

	return latest, latestTime
}

// latestNonCooldownVersion finds the most recently published version that is NOT in the
// tooNew set.
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
