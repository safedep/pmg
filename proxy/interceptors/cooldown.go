package interceptors

import (
	"fmt"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/Masterminds/semver"
	"github.com/safedep/pmg/internal/audit"
)

// cooldownIsWithinWindow reports whether a version published at publishDate is still
// within the cooldown window of cooldownDays. Returns withinCooldown, daysSincePublish,
// and daysRemaining.
func cooldownIsWithinWindow(publishDate time.Time, cooldownDays int) (withinCooldown bool, daysSincePublish int, daysRemaining int) {
	daysSincePublish = int(time.Since(publishDate).Hours() / 24)
	if daysSincePublish < 0 {
		daysSincePublish = 0
	}
	daysRemaining = cooldownDays - daysSincePublish
	if daysRemaining < 0 {
		daysRemaining = 0
	}
	return daysSincePublish < cooldownDays, daysSincePublish, daysRemaining
}

// cooldownOldestVersion returns the version with the earliest publish date.
// When all versions are in cooldown, this is the one closest to exiting the window.
func cooldownOldestVersion(dates map[string]time.Time) (string, time.Time) {
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

// recordCooldownStats records a cooldown block event. When all versions are blocked
// (remaining == 0), it reports the oldest version (closest to exiting cooldown).
// Otherwise, if a pinned version was stripped, it reports that specific version.
func recordCooldownStats(statsCollector *AnalysisStatsCollector, ecosystem packagev1.Ecosystem, packageName string, pinnedVersion string, dates map[string]time.Time, remaining int, cooldownDays int) {
	if statsCollector == nil {
		return
	}

	logCooldown := func(version string, publishDate time.Time, daysAgo, daysLeft int) {
		statsCollector.RecordCooldownBlocked(packageName, version, publishDate, daysAgo, daysLeft, cooldownDays)

		pv := &packagev1.PackageVersion{}
		pv.SetPackage(&packagev1.Package{})
		pv.GetPackage().SetName(packageName)
		pv.GetPackage().SetEcosystem(ecosystem)
		pv.SetVersion(version)
		audit.LogDependencyCooldown(pv, publishDate, cooldownDays, daysAgo, daysLeft)
	}

	if remaining == 0 {
		oldestVer, oldestDate := cooldownOldestVersion(dates)
		if oldestVer != "" {
			_, daysAgo, daysLeft := cooldownIsWithinWindow(oldestDate, cooldownDays)
			logCooldown(oldestVer, oldestDate, daysAgo, daysLeft)
		}
	} else if pinnedVersion != "" {
		if pinnedDate, ok := dates[pinnedVersion]; ok {
			if withinCooldown, daysAgo, daysLeft := cooldownIsWithinWindow(pinnedDate, cooldownDays); withinCooldown {
				logCooldown(pinnedVersion, pinnedDate, daysAgo, daysLeft)
			}
		}
	}
}

// cooldownHighestStableVersion returns the highest stable (non-prerelease) version
// among candidates that does not exceed upperBound, ordered by semver. This mirrors
// what npm treats as the "latest" dist-tag.
//
// Prerelease versions are excluded — semver classifies both alpha builds
// (e.g. 1.2.0-alpha.1) and platform-specific builds (e.g. 1.2.0-win32-arm64) as
// prereleases, so neither can be promoted to latest. Unparseable versions are skipped.
//
// upperBound is the version dist-tags.latest currently points to. Bounding by it keeps
// a repaired latest on the lineage the maintainer marked as latest, rather than
// promoting a higher major/minor published under a different channel (e.g. `next`).
// An empty or unparseable upperBound applies no upper bound.
func cooldownHighestStableVersion(candidates []string, upperBound string) string {
	var bound *semver.Version
	if upperBound != "" {
		if b, err := semver.NewVersion(upperBound); err == nil {
			// If latest itself points to a prerelease/platform build (e.g.
			// 1.0.0-win32-arm64), bound to its base release. The bound represents a
			// release line, and semver ranks 1.0.0 > 1.0.0-win32-arm64, so without
			// this the stable counterpart on the same line would be wrongly excluded.
			if b.Prerelease() != "" {
				if base, err := semver.NewVersion(fmt.Sprintf("%d.%d.%d", b.Major(), b.Minor(), b.Patch())); err == nil {
					b = base
				}
			}
			bound = b
		}
	}

	var latest string
	var latestVer *semver.Version
	for _, version := range candidates {
		ver, err := semver.NewVersion(version)
		if err != nil {
			continue
		}
		if ver.Prerelease() != "" {
			continue
		}
		if bound != nil && ver.GreaterThan(bound) {
			continue
		}
		if latestVer == nil || ver.GreaterThan(latestVer) {
			latest = version
			latestVer = ver
		}
	}
	return latest
}
