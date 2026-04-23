package interceptors

import "time"

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
func recordCooldownStats(statsCollector *AnalysisStatsCollector, packageName string, pinnedVersion string, dates map[string]time.Time, remaining int, cooldownDays int) {
	if statsCollector == nil {
		return
	}

	if remaining == 0 {
		oldestVer, oldestDate := cooldownOldestVersion(dates)
		if oldestVer != "" {
			_, daysAgo, daysLeft := cooldownIsWithinWindow(oldestDate, cooldownDays)
			statsCollector.RecordCooldownBlocked(packageName, oldestVer, oldestDate, daysAgo, daysLeft, cooldownDays)
		}
	} else if pinnedVersion != "" {
		if pinnedDate, ok := dates[pinnedVersion]; ok {
			if withinCooldown, daysAgo, daysLeft := cooldownIsWithinWindow(pinnedDate, cooldownDays); withinCooldown {
				statsCollector.RecordCooldownBlocked(packageName, pinnedVersion, pinnedDate, daysAgo, daysLeft, cooldownDays)
			}
		}
	}
}

// cooldownLatestEligibleVersion returns the most recently published version not in tooNew.
func cooldownLatestEligibleVersion(dates map[string]time.Time, tooNew map[string]bool) string {
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
