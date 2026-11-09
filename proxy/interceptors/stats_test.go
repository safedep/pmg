package interceptors

import (
	"testing"

	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
)

func TestRecordRuleBlockedCountsNoAnalysis(t *testing.T) {
	collector := NewAnalysisStatsCollector()

	collector.RecordRuleBlocked(&proxy.BlockContext{PackageName: "evil", PolicyRule: &proxy.PolicyRuleBlock{RuleID: "r_9c1"}})

	stats := collector.GetStats()
	assert.Zero(t, stats.TotalAnalyzed, "a package rule blocks with no analysis")
	assert.Equal(t, 1, stats.BlockedCount)
	assert.Len(t, collector.GetRuleBlocks(), 1)
}
