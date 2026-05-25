package interceptors

import (
	"testing"
	"time"

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
