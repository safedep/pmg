package interceptors

import (
	"fmt"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unanalyzedPkg(version string) *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM, Name: "flaky"},
		Version: version,
	}
}

func TestRecordUnanalyzedKeepsEachVersionOnce(t *testing.T) {
	collector := NewAnalysisStatsCollector()

	collector.RecordUnanalyzed(unanalyzedPkg("1.0.0"))
	collector.RecordUnanalyzed(unanalyzedPkg("1.0.0"))
	collector.RecordUnanalyzed(unanalyzedPkg("2.0.0"))

	unanalyzed, more := collector.GetUnanalyzedPackages()
	require.Len(t, unanalyzed, 2, "a retried download is kept once")
	assert.Equal(t, "1.0.0", unanalyzed[0].GetVersion())
	assert.Equal(t, "2.0.0", unanalyzed[1].GetVersion())
	assert.Zero(t, more)
	assert.Equal(t, AnalysisStats{}, collector.GetStats(), "a failed analysis is not counted as analyzed")
}

func TestRecordUnanalyzedCapsTheList(t *testing.T) {
	collector := NewAnalysisStatsCollector()

	for i := range maxUnanalyzedPackages + 3 {
		collector.RecordUnanalyzed(unanalyzedPkg(fmt.Sprintf("1.0.%d", i)))
	}
	collector.RecordUnanalyzed(unanalyzedPkg("1.0.0"))
	collector.RecordUnanalyzed(unanalyzedPkg(fmt.Sprintf("1.0.%d", maxUnanalyzedPackages)))

	unanalyzed, more := collector.GetUnanalyzedPackages()
	assert.Len(t, unanalyzed, maxUnanalyzedPackages)
	assert.Equal(t, 3, more, "a retried version is counted once, in the list or past it")
}

func TestRecordRuleBlockedCountsNoAnalysis(t *testing.T) {
	collector := NewAnalysisStatsCollector()

	collector.RecordRuleBlocked(&proxy.BlockContext{PackageName: "evil", PolicyRule: &proxy.PolicyRuleBlock{RuleID: "r_9c1"}})

	stats := collector.GetStats()
	assert.Zero(t, stats.TotalAnalyzed, "a package rule blocks with no analysis")
	assert.Equal(t, 1, stats.BlockedCount)
	assert.Len(t, collector.GetRuleBlocks(), 1)
}

func TestNoVerdictBlocksCapAndHeal(t *testing.T) {
	collector := NewAnalysisStatsCollector()
	block := func(version string) *proxy.BlockContext {
		return &proxy.BlockContext{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM, PackageName: "flaky", PackageVersion: version}
	}

	for i := range maxUnanalyzedPackages + 3 {
		collector.RecordNoVerdictBlocked(block(fmt.Sprintf("1.0.%d", i)))
	}
	collector.RecordNoVerdictBlocked(block("1.0.0"))

	blocks, more := collector.GetNoVerdictBlocks()
	assert.Len(t, blocks, maxUnanalyzedPackages)
	assert.Equal(t, 3, more)
	assert.Equal(t, maxUnanalyzedPackages+3, collector.GetStats().BlockedCount, "a retried version counts once")

	collector.ClearNoVerdictBlock(packagev1.Ecosystem_ECOSYSTEM_NPM, "flaky", "1.0.0")
	collector.ClearNoVerdictBlock(packagev1.Ecosystem_ECOSYSTEM_NPM, "flaky", "1.0.0")
	collector.ClearNoVerdictBlock(packagev1.Ecosystem_ECOSYSTEM_NPM, "flaky", fmt.Sprintf("1.0.%d", maxUnanalyzedPackages))

	blocks, more = collector.GetNoVerdictBlocks()
	assert.Len(t, blocks, maxUnanalyzedPackages-1)
	assert.Equal(t, 2, more)
	assert.Equal(t, maxUnanalyzedPackages+1, collector.GetStats().BlockedCount, "a heal counts once, in the list or past it")
	assert.False(t, collector.HasNoVerdictBlock(block("1.0.0")))
	assert.True(t, collector.HasNoVerdictBlock(block("1.0.1")))
}
