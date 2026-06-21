package interceptors

import (
	"fmt"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/Masterminds/semver"
	"github.com/safedep/dry/log"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
)

// cooldownExemptions describes the in-window versions that survive cooldown
// stripping and why. all is the full exempt set; skipListed is the subset
// attributable to dependency_cooldown.skip and is the only set that produces an
// audit event — trusted versions surface as install_trusted_allowed via the
// proxy fast-allow gate at download time.
type cooldownExemptions struct {
	all        map[string]bool
	skipListed []string
}

// cooldownExemptVersions classifies the versions that must survive stripping
// even though they fall within the cooldown window: those trusted via
// trusted_packages or on the dependency_cooldown.skip list. Only in-window
// versions are examined, bounding the per-version trusted lookup to recent
// releases rather than the full (potentially large) version history. A version
// that is both trusted and skip-listed is attributed to trusted, mirroring the
// download-path precedence where the fast-allow gate wins.
func cooldownExemptVersions(ecosystem packagev1.Ecosystem, name string, skip pmgconfig.CooldownSkipInfo, dates map[string]time.Time, cooldownDays int) cooldownExemptions {
	exempt := cooldownExemptions{all: make(map[string]bool)}
	for v, publishDate := range dates {
		if within, _, _ := cooldownIsWithinWindow(publishDate, cooldownDays); !within {
			continue
		}
		switch {
		case pmgconfig.IsTrustedPackageRef(ecosystem, name, v):
			exempt.all[v] = true
		case skip.SkipAll:
			// A whole-package skip is one waiver, not a per-version exemption:
			// keep the version but never emit per-version audit events.
			// HandleMetadataRequest also short-circuits this case upstream.
			exempt.all[v] = true
		case skip.ExemptsVersion(v):
			exempt.all[v] = true
			exempt.skipListed = append(exempt.skipListed, v)
		}
	}
	return exempt
}

// auditCooldownSkips emits one dependency_cooldown_skipped audit event per
// version that the skip list exempted from an active cooldown window. It is
// called from the metadata modifier, where publish dates are known, so the
// event only fires for versions a live cooldown would otherwise have stripped.
func auditCooldownSkips(requestID string, ecosystem packagev1.Ecosystem, name string, exempt cooldownExemptions) {
	for _, version := range exempt.skipListed {
		log.Infof("[%s] Cooldown: %s@%s exempt by %s", requestID, name, version, audit.CooldownSkipReason)

		pv := &packagev1.PackageVersion{}
		pv.SetPackage(&packagev1.Package{})
		pv.GetPackage().SetName(name)
		pv.GetPackage().SetEcosystem(ecosystem)
		pv.SetVersion(version)
		audit.LogCooldownSkipped(pv)
	}
}

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
