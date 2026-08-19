package interceptors

import (
	"sort"
	"sync"
	"time"

	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/internal/models"
)

// AnalysisStats contains aggregated statistics from analysis results
type AnalysisStats struct {
	TotalAnalyzed        int
	AllowedCount         int
	ConfirmedCount       int
	BlockedCount         int
	UserCancelledCount   int
	CooldownBlockedCount int
}

// AnalysisStatsCollector tracks analysis statistics during proxy execution.
// It is separate from the cache to allow different cache implementations
// without coupling them to reporting concerns.
type AnalysisStatsCollector struct {
	mu                sync.RWMutex
	stats             AnalysisStats
	blockedPackages   []*analyzer.PackageVersionAnalysisResult
	confirmedPackages []*analyzer.PackageVersionAnalysisResult
	cooldownBlocks    []models.CooldownBlock

	// cooldownWithheld is keyed by package name, then version, holding days
	// left. Metadata for one package can be fetched several times during an
	// install, so recording must deduplicate rather than append.
	cooldownWithheld map[string]map[string]int
}

// NewAnalysisStatsCollector creates a new stats collector
func NewAnalysisStatsCollector() *AnalysisStatsCollector {
	return &AnalysisStatsCollector{}
}

// RecordAllowed records a package that was allowed (safe)
func (c *AnalysisStatsCollector) RecordAllowed(result *analyzer.PackageVersionAnalysisResult) {
	if result == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.TotalAnalyzed++
	c.stats.AllowedCount++
}

// RecordBlocked records a package that was automatically blocked (ActionBlock)
func (c *AnalysisStatsCollector) RecordBlocked(result *analyzer.PackageVersionAnalysisResult) {
	if result == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.TotalAnalyzed++
	c.stats.BlockedCount++
	c.blockedPackages = append(c.blockedPackages, result)
}

// RecordUserCancelled records a package that was blocked because user declined confirmation (ActionConfirm declined)
func (c *AnalysisStatsCollector) RecordUserCancelled(result *analyzer.PackageVersionAnalysisResult) {
	if result == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.TotalAnalyzed++
	c.stats.UserCancelledCount++

	// User cancelled packages are counted as blocked as well
	c.stats.BlockedCount++

	c.blockedPackages = append(c.blockedPackages, result)
}

// RecordConfirmed records a package where user confirmed installation despite warning
func (c *AnalysisStatsCollector) RecordConfirmed(result *analyzer.PackageVersionAnalysisResult) {
	if result == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.TotalAnalyzed++
	c.stats.ConfirmedCount++
	c.confirmedPackages = append(c.confirmedPackages, result)
}

// GetStats returns the current statistics
func (c *AnalysisStatsCollector) GetStats() AnalysisStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.stats
}

// GetBlockedPackages returns all blocked packages
func (c *AnalysisStatsCollector) GetBlockedPackages() []*analyzer.PackageVersionAnalysisResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make([]*analyzer.PackageVersionAnalysisResult, len(c.blockedPackages))
	copy(result, c.blockedPackages)
	return result
}

// GetConfirmedPackages returns all confirmed packages
func (c *AnalysisStatsCollector) GetConfirmedPackages() []*analyzer.PackageVersionAnalysisResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make([]*analyzer.PackageVersionAnalysisResult, len(c.confirmedPackages))
	copy(result, c.confirmedPackages)
	return result
}

// RecordCooldownBlocked records a package blocked by the dependency cooldown policy.
func (c *AnalysisStatsCollector) RecordCooldownBlocked(name, version string, publishDate time.Time, daysAgo, daysLeft, cooldownDays int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.TotalAnalyzed++
	c.stats.BlockedCount++
	c.stats.CooldownBlockedCount++
	c.cooldownBlocks = append(c.cooldownBlocks, models.CooldownBlock{
		Name:         name,
		Version:      version,
		PublishDate:  publishDate,
		DaysAgo:      daysAgo,
		DaysLeft:     daysLeft,
		CooldownDays: cooldownDays,
	})
}

// GetCooldownBlocks returns all packages blocked by the cooldown policy.
func (c *AnalysisStatsCollector) GetCooldownBlocks() []models.CooldownBlock {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]models.CooldownBlock, len(c.cooldownBlocks))
	copy(result, c.cooldownBlocks)
	return result
}

// RecordCooldownWithheld records versions stripped from a package's metadata
// while eligible versions remained. Withheld versions are not blocks: they do
// not count toward analyzed or blocked totals.
func (c *AnalysisStatsCollector) RecordCooldownWithheld(name string, versions []models.CooldownWithheldVersion) {
	if len(versions) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cooldownWithheld == nil {
		c.cooldownWithheld = make(map[string]map[string]int)
	}
	if c.cooldownWithheld[name] == nil {
		c.cooldownWithheld[name] = make(map[string]int)
	}
	for _, v := range versions {
		c.cooldownWithheld[name][v.Version] = v.DaysLeft
	}
}

// GetCooldownWithheld returns the withheld records sorted by package name and
// version for stable rendering.
func (c *AnalysisStatsCollector) GetCooldownWithheld() []models.CooldownWithheld {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]models.CooldownWithheld, 0, len(c.cooldownWithheld))
	for name, versions := range c.cooldownWithheld {
		entry := models.CooldownWithheld{Name: name}
		for version, daysLeft := range versions {
			entry.Versions = append(entry.Versions, models.CooldownWithheldVersion{
				Version:  version,
				DaysLeft: daysLeft,
			})
		}
		sort.Slice(entry.Versions, func(i, j int) bool {
			return entry.Versions[i].Version < entry.Versions[j].Version
		})
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
