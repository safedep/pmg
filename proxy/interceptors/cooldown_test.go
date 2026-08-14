package interceptors

import (
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestCooldownExemptVersions(t *testing.T) {
	setTrustedPackagesForTest(t, []pmgconfig.TrustedPackage{
		{Purl: "pkg:npm/pkg@2.0.0"},
		{Purl: "pkg:npm/pkg@3.0.0"}, // both trusted and skip-listed below
	})

	now := time.Now()
	day := 24 * time.Hour
	dates := map[string]time.Time{
		"1.0.0": now.Add(-1 * day),   // in window, skip-listed -> audited
		"2.0.0": now.Add(-1 * day),   // in window, trusted -> exempt, not audited
		"3.0.0": now.Add(-1 * day),   // in window, trusted + skip-listed -> trusted wins
		"4.0.0": now.Add(-100 * day), // skip-listed but out of window -> not exempt
		"5.0.0": now.Add(-1 * day),   // in window, neither -> stripped
	}
	skip := pmgconfig.CooldownSkipInfo{Versions: map[string]bool{
		"1.0.0": true,
		"3.0.0": true,
		"4.0.0": true,
	}}

	exempt := cooldownExemptVersions(packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg", skip, dates, 5)

	assert.ElementsMatch(t, []string{"1.0.0", "2.0.0", "3.0.0"}, keysOf(exempt.all))
	// Only the in-window, skip-listed, non-trusted version is audited.
	assert.Equal(t, []string{"1.0.0"}, exempt.skipListed)
}

// An out-of-window skip-listed version, or a zero-day cooldown, must not be
// reported as a cooldown bypass: nothing was actually within an active window.
func TestCooldownExemptVersions_NoActiveWindow(t *testing.T) {
	setTrustedPackagesForTest(t, nil)

	now := time.Now()
	day := 24 * time.Hour
	dates := map[string]time.Time{"1.0.0": now.Add(-100 * day)}
	skip := pmgconfig.CooldownSkipInfo{Versions: map[string]bool{"1.0.0": true}}

	oldVersion := cooldownExemptVersions(packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg", skip, dates, 5)
	assert.Empty(t, oldVersion.skipListed)
	assert.Empty(t, oldVersion.all)

	freshDates := map[string]time.Time{"1.0.0": now.Add(-1 * day)}
	zeroDay := cooldownExemptVersions(packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg", skip, freshDates, 0)
	assert.Empty(t, zeroDay.skipListed)
	assert.Empty(t, zeroDay.all)
}

// A whole-package skip (version-less entry) exempts every version but must not
// produce per-version audit events — it is a single package-level waiver.
func TestCooldownExemptVersions_SkipAll(t *testing.T) {
	setTrustedPackagesForTest(t, nil)

	now := time.Now()
	day := 24 * time.Hour
	dates := map[string]time.Time{
		"1.0.0": now.Add(-1 * day),
		"2.0.0": now.Add(-1 * day),
	}
	skip := pmgconfig.CooldownSkipInfo{SkipAll: true}

	exempt := cooldownExemptVersions(packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg", skip, dates, 5)
	assert.ElementsMatch(t, []string{"1.0.0", "2.0.0"}, keysOf(exempt.all))
	assert.Empty(t, exempt.skipListed, "whole-package skip must not emit per-version events")
}

func keysOf(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestCooldownIsWithinWindow(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour

	tests := []struct {
		name                 string
		publishDate          time.Time
		cooldownDays         int
		wantWithinCooldown   bool
		wantDaysSincePublish int
		wantDaysRemaining    int
	}{
		{
			name:                 "published today with 30 day cooldown",
			publishDate:          now,
			cooldownDays:         30,
			wantWithinCooldown:   true,
			wantDaysSincePublish: 0,
			wantDaysRemaining:    30,
		},
		{
			name:                 "published exactly at cooldown boundary",
			publishDate:          now.Add(-30 * day),
			cooldownDays:         30,
			wantWithinCooldown:   false,
			wantDaysSincePublish: 30,
			wantDaysRemaining:    0,
		},
		{
			name:                 "published one day before cooldown expires",
			publishDate:          now.Add(-29 * day),
			cooldownDays:         30,
			wantWithinCooldown:   true,
			wantDaysSincePublish: 29,
			wantDaysRemaining:    1,
		},
		{
			name:                 "published well beyond cooldown",
			publishDate:          now.Add(-365 * day),
			cooldownDays:         30,
			wantWithinCooldown:   false,
			wantDaysSincePublish: 365,
			wantDaysRemaining:    0,
		},
		{
			name:                 "zero cooldown days",
			publishDate:          now,
			cooldownDays:         0,
			wantWithinCooldown:   false,
			wantDaysSincePublish: 0,
			wantDaysRemaining:    0,
		},
		{
			name:                 "future publish date clamped to zero days",
			publishDate:          now.Add(5 * day),
			cooldownDays:         30,
			wantWithinCooldown:   true,
			wantDaysSincePublish: 0,
			wantDaysRemaining:    30,
		},
		{
			name:                 "one day cooldown with publish today",
			publishDate:          now,
			cooldownDays:         1,
			wantWithinCooldown:   true,
			wantDaysSincePublish: 0,
			wantDaysRemaining:    1,
		},
		{
			name:                 "one day cooldown with publish yesterday",
			publishDate:          now.Add(-1 * day),
			cooldownDays:         1,
			wantWithinCooldown:   false,
			wantDaysSincePublish: 1,
			wantDaysRemaining:    0,
		},
		{
			name:                 "max int cooldown days does not overflow",
			publishDate:          now.Add(-1 * day),
			cooldownDays:         int(^uint(0) >> 1),
			wantWithinCooldown:   true,
			wantDaysSincePublish: 1,
			wantDaysRemaining:    int(^uint(0)>>1) - 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withinCooldown, daysSincePublish, daysRemaining := cooldownIsWithinWindow(tt.publishDate, tt.cooldownDays)
			assert.Equal(t, tt.wantWithinCooldown, withinCooldown, "withinCooldown")
			assert.Equal(t, tt.wantDaysSincePublish, daysSincePublish, "daysSincePublish")
			assert.Equal(t, tt.wantDaysRemaining, daysRemaining, "daysRemaining")
		})
	}
}

func TestCooldownOldestVersion(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour

	t.Run("returns version with earliest publish date", func(t *testing.T) {
		dates := map[string]time.Time{
			"1.0.0": now.Add(-30 * day),
			"2.0.0": now.Add(-10 * day),
			"3.0.0": now.Add(-1 * day),
		}
		ver, ts := cooldownOldestVersion(dates)
		assert.Equal(t, "1.0.0", ver)
		assert.False(t, ts.IsZero())
	})

	t.Run("single version", func(t *testing.T) {
		dates := map[string]time.Time{"1.0.0": now.Add(-5 * day)}
		ver, _ := cooldownOldestVersion(dates)
		assert.Equal(t, "1.0.0", ver)
	})

	t.Run("empty map returns empty string and zero time", func(t *testing.T) {
		ver, ts := cooldownOldestVersion(map[string]time.Time{})
		assert.Empty(t, ver)
		assert.True(t, ts.IsZero())
	})
}

func TestCooldownHighestStableVersion(t *testing.T) {
	tests := []struct {
		name       string
		candidates []string
		upperBound string
		want       string
	}{
		{
			name:       "highest stable by semver, not lexical",
			candidates: []string{"0.9.0", "0.10.0", "0.2.0"},
			want:       "0.10.0",
		},
		{
			name:       "excludes prerelease and platform builds",
			candidates: []string{"0.132.0", "0.132.5-win32-arm64", "0.133.0-alpha.3", "0.131.0"},
			want:       "0.132.0",
		},
		{
			name:       "no stable version returns empty",
			candidates: []string{"1.0.0-alpha.1", "1.0.0-win32-arm64"},
			want:       "",
		},
		{
			name:       "unparseable versions skipped",
			candidates: []string{"latest", "not-a-version", "1.2.3"},
			want:       "1.2.3",
		},
		{
			name:       "single stable",
			candidates: []string{"2.0.0"},
			want:       "2.0.0",
		},
		{
			name:       "empty input",
			candidates: []string{},
			want:       "",
		},
		{
			name:       "upper bound excludes higher major from another channel",
			candidates: []string{"1.4.0", "2.0.0"},
			upperBound: "1.5.0",
			want:       "1.4.0",
		},
		{
			name:       "upper bound allows versions at or below it",
			candidates: []string{"1.4.0", "1.5.0", "2.0.0"},
			upperBound: "1.5.0",
			want:       "1.5.0",
		},
		{
			name:       "unparseable upper bound applies no bound",
			candidates: []string{"1.4.0", "2.0.0"},
			upperBound: "not-a-version",
			want:       "2.0.0",
		},
		{
			name:       "prerelease upper bound does not exclude its stable counterpart",
			candidates: []string{"1.0.0", "0.9.0"},
			upperBound: "1.0.0-win32-arm64",
			want:       "1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, cooldownHighestStableVersion(tt.candidates, tt.upperBound))
		})
	}
}

func TestRecordCooldownStats(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour

	tests := []struct {
		name          string
		pinnedVersion string
		dates         map[string]time.Time
		stripped      []string
		remaining     int
		wantBlocked   []string
		wantWithheld  map[string][]string
	}{
		{
			name: "all versions stripped records oldest as block",
			dates: map[string]time.Time{
				"1.0.0": now.Add(-3 * day),
				"1.1.0": now.Add(-1 * day),
			},
			stripped:     []string{"1.0.0", "1.1.0"},
			remaining:    0,
			wantBlocked:  []string{"1.0.0"},
			wantWithheld: map[string][]string{},
		},
		{
			name:          "stripped pinned version records a block",
			pinnedVersion: "2.0.0",
			dates: map[string]time.Time{
				"1.0.0": now.Add(-100 * day),
				"2.0.0": now.Add(-1 * day),
			},
			stripped:     []string{"2.0.0"},
			remaining:    1,
			wantBlocked:  []string{"2.0.0"},
			wantWithheld: map[string][]string{},
		},
		{
			name:          "surviving pinned version records others as withheld",
			pinnedVersion: "2.0.0",
			dates: map[string]time.Time{
				"1.0.0": now.Add(-100 * day),
				"2.0.0": now.Add(-1 * day), // exempt: survived stripping
				"2.1.0": now.Add(-1 * day),
			},
			stripped:     []string{"2.1.0"},
			remaining:    2,
			wantBlocked:  nil,
			wantWithheld: map[string][]string{"pkg": {"2.1.0"}},
		},
		{
			name: "no pin with eligible versions records withheld only",
			dates: map[string]time.Time{
				"1.0.0": now.Add(-100 * day),
				"2.0.0": now.Add(-1 * day),
				"2.1.0": now.Add(-2 * day),
			},
			stripped:     []string{"2.0.0", "2.1.0"},
			remaining:    1,
			wantBlocked:  nil,
			wantWithheld: map[string][]string{"pkg": {"2.0.0", "2.1.0"}},
		},
		{
			name: "nothing stripped records nothing",
			dates: map[string]time.Time{
				"1.0.0": now.Add(-100 * day),
			},
			stripped:     nil,
			remaining:    1,
			wantBlocked:  nil,
			wantWithheld: map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := NewAnalysisStatsCollector()
			recordCooldownStats(collector, packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg", tt.pinnedVersion, tt.dates, tt.stripped, tt.remaining, 5)

			var blocked []string
			for _, b := range collector.GetCooldownBlocks() {
				blocked = append(blocked, b.Version)
			}
			assert.ElementsMatch(t, tt.wantBlocked, blocked)

			withheld := map[string][]string{}
			for _, w := range collector.GetCooldownWithheld() {
				for _, v := range w.Versions {
					withheld[w.Name] = append(withheld[w.Name], v.Version)
				}
			}
			assert.Equal(t, tt.wantWithheld, withheld)
		})
	}
}

func TestRecordCooldownStats_NilCollector(t *testing.T) {
	assert.NotPanics(t, func() {
		recordCooldownStats(nil, packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg", "", nil, []string{"1.0.0"}, 0, 5)
	})
}

func TestRecordCooldownWithheld_DeduplicatesAcrossFetches(t *testing.T) {
	collector := NewAnalysisStatsCollector()

	versions := []models.CooldownWithheldVersion{
		{Version: "2.0.0", DaysLeft: 4},
		{Version: "2.1.0", DaysLeft: 5},
	}
	collector.RecordCooldownWithheld("pkg", versions)
	collector.RecordCooldownWithheld("pkg", versions)
	collector.RecordCooldownWithheld("other", []models.CooldownWithheldVersion{{Version: "1.0.0", DaysLeft: 1}})

	withheld := collector.GetCooldownWithheld()
	assert.Len(t, withheld, 2)
	assert.Equal(t, "other", withheld[0].Name)
	assert.Equal(t, "pkg", withheld[1].Name)
	assert.Equal(t, versions, withheld[1].Versions)

	stats := collector.GetStats()
	assert.Equal(t, 0, stats.TotalAnalyzed, "withheld versions are not analyzed packages")
	assert.Equal(t, 0, stats.BlockedCount, "withheld versions are not blocks")
	assert.Equal(t, 0, stats.CooldownBlockedCount)
}
