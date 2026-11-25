package interceptors

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordUnanalyzedKeepsEachVersionOnce(t *testing.T) {
	collector := NewAnalysisStatsCollector()
	pkg := func(version string) *packagev1.PackageVersion {
		return &packagev1.PackageVersion{
			Package: &packagev1.Package{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM, Name: "flaky"},
			Version: version,
		}
	}

	collector.RecordUnanalyzed(pkg("1.0.0"))
	collector.RecordUnanalyzed(pkg("1.0.0"))
	collector.RecordUnanalyzed(pkg("2.0.0"))

	unanalyzed := collector.GetUnanalyzedPackages()
	require.Len(t, unanalyzed, 2, "a retried download is kept once")
	assert.Equal(t, "1.0.0", unanalyzed[0].GetVersion())
	assert.Equal(t, "2.0.0", unanalyzed[1].GetVersion())
	assert.Equal(t, AnalysisStats{}, collector.GetStats(), "a failed analysis is not counted as analyzed")
}

func TestRecordRuleBlockedCountsNoAnalysis(t *testing.T) {
	collector := NewAnalysisStatsCollector()

	collector.RecordRuleBlocked(&proxy.BlockContext{PackageName: "evil", PolicyRule: &proxy.PolicyRuleBlock{RuleID: "r_9c1"}})

	stats := collector.GetStats()
	assert.Zero(t, stats.TotalAnalyzed, "a package rule blocks with no analysis")
	assert.Equal(t, 1, stats.BlockedCount)
	assert.Len(t, collector.GetRuleBlocks(), 1)
}
