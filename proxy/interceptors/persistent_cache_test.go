package interceptors

import (
	"os"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allowResult() *analyzer.PackageVersionAnalysisResult {
	return &analyzer.PackageVersionAnalysisResult{
		Action:       analyzer.ActionAllow,
		AnalysisID:   "analysis-123",
		ReferenceURL: "https://example.test/report",
		Summary:      "clean",
	}
}

// newCache is a helper returning a persistent cache rooted at dir. A fresh
// instance has an empty in-memory tier, so reads from it exercise the disk tier.
func newCache(t *testing.T, dir string, ttl time.Duration) *persistentAnalysisCache {
	t.Helper()
	c, err := NewPersistentAnalysisCache(dir, ttl)
	require.NoError(t, err)
	return c
}

func TestPersistentCache_AllowVerdictSurvivesAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	// Production keys the cache with ecosystem.String() (e.g. "ECOSYSTEM_NPM"),
	// which the persistent cache reverses back into the enum on read.
	npmEco := packagev1.Ecosystem_ECOSYSTEM_NPM.String()
	newCache(t, dir, time.Hour).Set(npmEco, "express", "4.18.0", allowResult())

	// A brand-new instance has an empty L1, so a hit here came from disk.
	got, ok := newCache(t, dir, time.Hour).Get(npmEco, "express", "4.18.0")
	require.True(t, ok, "expected disk hit for persisted ALLOW verdict")
	assert.Equal(t, analyzer.ActionAllow, got.Action)
	assert.Equal(t, "express", got.PackageVersion.GetPackage().GetName())
	assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_NPM, got.PackageVersion.GetPackage().GetEcosystem())
	assert.Equal(t, "4.18.0", got.PackageVersion.GetVersion())
	assert.Equal(t, "analysis-123", got.AnalysisID)
}

func TestPersistentCache_NonAllowVerdictsNotPersisted(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*analyzer.PackageVersionAnalysisResult)
	}{
		{"block", func(r *analyzer.PackageVersionAnalysisResult) { r.Action = analyzer.ActionBlock }},
		{"confirm", func(r *analyzer.PackageVersionAnalysisResult) { r.Action = analyzer.ActionConfirm }},
		{"allow but malware", func(r *analyzer.PackageVersionAnalysisResult) { r.IsMalware = true }},
		{"allow but tenant-excluded", func(r *analyzer.PackageVersionAnalysisResult) { r.IsExcluded = true }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			result := allowResult()
			tc.mutate(result)

			newCache(t, dir, time.Hour).Set("npm", "evil", "1.0.0", result)

			_, ok := newCache(t, dir, time.Hour).Get("npm", "evil", "1.0.0")
			assert.False(t, ok, "non-clean verdict must not be persisted across runs")
		})
	}
}

func TestPersistentCache_ExpiredEntryIsMiss(t *testing.T) {
	dir := t.TempDir()
	newCache(t, dir, time.Millisecond).Set("npm", "lodash", "4.17.21", allowResult())

	time.Sleep(10 * time.Millisecond)

	_, ok := newCache(t, dir, time.Millisecond).Get("npm", "lodash", "4.17.21")
	assert.False(t, ok, "entry older than TTL must be a miss")
}

func TestPersistentCache_NonPositiveTTLDisablesPersistence(t *testing.T) {
	dir := t.TempDir()
	newCache(t, dir, 0).Set("npm", "react", "18.0.0", allowResult())

	_, ok := newCache(t, dir, 0).Get("npm", "react", "18.0.0")
	assert.False(t, ok, "ttl<=0 must behave like no persistent cache")
}

func TestPersistentCache_InMemoryHitWithinSameInstance(t *testing.T) {
	// Even with a non-positive TTL (no disk persistence), Set must populate the
	// in-memory tier so a repeat lookup within the same run still hits.
	c := newCache(t, t.TempDir(), 0)
	c.Set("npm", "react", "18.0.0", allowResult())

	_, ok := c.Get("npm", "react", "18.0.0")
	assert.True(t, ok, "same-instance lookup should hit the in-memory tier")
}

func TestPersistentCache_ScopedNameRoundTrips(t *testing.T) {
	dir := t.TempDir()
	newCache(t, dir, time.Hour).Set("npm", "@scope/pkg", "2.0.0", allowResult())

	got, ok := newCache(t, dir, time.Hour).Get("npm", "@scope/pkg", "2.0.0")
	require.True(t, ok, "scoped package name should persist and round-trip")
	assert.Equal(t, "@scope/pkg", got.PackageVersion.GetPackage().GetName())
}

func TestPersistentCache_CorruptRecordIsMiss(t *testing.T) {
	dir := t.TempDir()
	c := newCache(t, dir, time.Hour)

	path := c.recordPath("npm", "express", "4.18.0")
	require.NoError(t, os.WriteFile(path, []byte("{not valid json"), 0o600))

	_, ok := c.Get("npm", "express", "4.18.0")
	assert.False(t, ok, "corrupt record must be treated as a miss")

	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "corrupt record should be cleaned up")
}
