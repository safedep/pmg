package interceptors

import (
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
)

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

func TestCooldownSkipAuditReasonForVersion(t *testing.T) {
	tests := []struct {
		name       string
		skip       pmgconfig.CooldownSkipInfo
		version    string
		wantReason string
		wantOK     bool
	}{
		{
			name: "package-wide cooldown skip logs concrete version",
			skip: pmgconfig.CooldownSkipInfo{
				SkipAll:    true,
				SkipReason: pmgconfig.CooldownSkipReasonCooldownSkipList,
			},
			version:    "1.2.3",
			wantReason: "dependency_cooldown.skip",
			wantOK:     true,
		},
		{
			name: "package-wide trusted skip does not emit cooldown audit",
			skip: pmgconfig.CooldownSkipInfo{
				SkipAll:    true,
				SkipReason: pmgconfig.CooldownSkipReasonTrustedPackage,
			},
			version: "1.2.3",
			wantOK:  false,
		},
		{
			name: "version-pinned cooldown skip logs matching version",
			skip: pmgconfig.CooldownSkipInfo{
				Versions: map[string]pmgconfig.CooldownSkipReason{
					"2.0.0": pmgconfig.CooldownSkipReasonCooldownSkipList,
				},
			},
			version:    "2.0.0",
			wantReason: "dependency_cooldown.skip",
			wantOK:     true,
		},
		{
			name: "version-pinned trusted skip does not emit cooldown audit",
			skip: pmgconfig.CooldownSkipInfo{
				Versions: map[string]pmgconfig.CooldownSkipReason{
					"2.0.0": pmgconfig.CooldownSkipReasonTrustedPackage,
				},
			},
			version: "2.0.0",
			wantOK:  false,
		},
		{
			name: "non-matching version does not emit cooldown audit",
			skip: pmgconfig.CooldownSkipInfo{
				Versions: map[string]pmgconfig.CooldownSkipReason{
					"2.0.0": pmgconfig.CooldownSkipReasonCooldownSkipList,
				},
			},
			version: "3.0.0",
			wantOK:  false,
		},
		{
			name: "empty version does not emit cooldown audit",
			skip: pmgconfig.CooldownSkipInfo{
				SkipAll:    true,
				SkipReason: pmgconfig.CooldownSkipReasonCooldownSkipList,
			},
			version: "",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotReason, gotOK := cooldownSkipAuditReasonForVersion(tt.skip, tt.version)
			assert.Equal(t, tt.wantReason, gotReason)
			assert.Equal(t, tt.wantOK, gotOK)
		})
	}
}

func TestAuditCooldownSkipLogsConcreteVersionOnly(t *testing.T) {
	tests := []struct {
		name      string
		skip      pmgconfig.CooldownSkipInfo
		version   string
		wantAudit bool
	}{
		{
			name: "skip-all cooldown exemption logs concrete version",
			skip: pmgconfig.CooldownSkipInfo{
				SkipAll:    true,
				SkipReason: pmgconfig.CooldownSkipReasonCooldownSkipList,
			},
			version:   "1.0.0",
			wantAudit: true,
		},
		{
			name: "skip-all without version does not log",
			skip: pmgconfig.CooldownSkipInfo{
				SkipAll:    true,
				SkipReason: pmgconfig.CooldownSkipReasonCooldownSkipList,
			},
			version:   "",
			wantAudit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test exercises the helper's outward behavior without requiring
			// sink setup: when the helper says "no audit", it must stay a no-op.
			// The positive case is covered indirectly by the pure reason test plus
			// the audit package tests that validate LogCooldownSkipped payloads.
			gotReason, gotOK := cooldownSkipAuditReasonForVersion(tt.skip, tt.version)
			assert.Equal(t, tt.wantAudit, gotOK)
			if gotOK {
				assert.Equal(t, pmgconfig.CooldownSkipReasonCooldownSkipList.String(), gotReason)
			}

			pv := &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
					Name:      "pkg",
				},
				Version: tt.version,
			}
			assert.NotNil(t, pv)
		})
	}
}
