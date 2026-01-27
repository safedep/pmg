package interceptors

import (
	"sync"

	"github.com/safedep/pmg/analyzer"
)

// AnalysisStats contains aggregated statistics from analysis results
type AnalysisStats struct {
	TotalAnalyzed      int
	AllowedCount       int
	ConfirmedCount     int
	BlockedCount       int
	UserCancelledCount int
}

// AnalysisStatsCollector tracks analysis statistics during proxy execution.
// It is separate from the cache to allow different cache implementations
// without coupling them to reporting concerns.
type AnalysisStatsCollector struct {
	mu                sync.RWMutex
	stats             AnalysisStats
	blockedPackages   []*analyzer.PackageVersionAnalysisResult
	confirmedPackages []*analyzer.PackageVersionAnalysisResult
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
