package malysiscache

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPkg() *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{Name: "express", Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
		Version: "4.18.0",
	}
}

func allowResult() *analyzer.PackageVersionAnalysisResult {
	return &analyzer.PackageVersionAnalysisResult{
		Action:       analyzer.ActionAllow,
		AnalysisID:   "analysis-1",
		ReferenceURL: "https://example.test/r",
		Summary:      "clean",
	}
}

func openCache(t *testing.T, ttl time.Duration) (*SQLiteCache, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewSQLiteCache(path, ttl)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c, path
}

func TestSQLiteCache_SetThenGet(t *testing.T) {
	c, _ := openCache(t, time.Hour)
	ctx := context.Background()

	require.NoError(t, c.Set(ctx, testPkg(), allowResult()))

	got, ok, err := c.Get(ctx, testPkg())
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, analyzer.ActionAllow, got.Action)
	assert.Equal(t, "analysis-1", got.AnalysisID)
	assert.Equal(t, "express", got.PackageVersion.GetPackage().GetName())
	assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_NPM, got.PackageVersion.GetPackage().GetEcosystem())
	assert.Equal(t, "4.18.0", got.PackageVersion.GetVersion())
}

func TestSQLiteCache_PersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	ctx := context.Background()

	c1, err := NewSQLiteCache(path, time.Hour)
	require.NoError(t, err)
	require.NoError(t, c1.Set(ctx, testPkg(), allowResult()))
	require.NoError(t, c1.Close())

	c2, err := NewSQLiteCache(path, time.Hour)
	require.NoError(t, err)
	defer func() { _ = c2.Close() }()

	_, ok, err := c2.Get(ctx, testPkg())
	require.NoError(t, err)
	assert.True(t, ok, "verdict should survive reopening the database")
}

func TestSQLiteCache_MissForUnknownPackage(t *testing.T) {
	c, _ := openCache(t, time.Hour)
	_, ok, err := c.Get(context.Background(), testPkg())
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSQLiteCache_ExpiredEntryIsMiss(t *testing.T) {
	c, _ := openCache(t, time.Millisecond)
	ctx := context.Background()

	require.NoError(t, c.Set(ctx, testPkg(), allowResult()))
	time.Sleep(10 * time.Millisecond)

	_, ok, err := c.Get(ctx, testPkg())
	require.NoError(t, err)
	assert.False(t, ok, "entry older than ttl must be a miss")
}

func TestSQLiteCache_NonPositiveTTLDisables(t *testing.T) {
	c, _ := openCache(t, 0)
	ctx := context.Background()

	require.NoError(t, c.Set(ctx, testPkg(), allowResult()))
	_, ok, err := c.Get(ctx, testPkg())
	require.NoError(t, err)
	assert.False(t, ok, "ttl<=0 disables caching")
}

func TestSQLiteCache_NilPackageIsMiss(t *testing.T) {
	c, _ := openCache(t, time.Hour)
	_, ok, err := c.Get(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSQLiteCache_OverwriteExistingEntry(t *testing.T) {
	c, _ := openCache(t, time.Hour)
	ctx := context.Background()

	require.NoError(t, c.Set(ctx, testPkg(), allowResult()))

	updated := allowResult()
	updated.AnalysisID = "analysis-2"
	require.NoError(t, c.Set(ctx, testPkg(), updated))

	got, ok, err := c.Get(ctx, testPkg())
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "analysis-2", got.AnalysisID)
}
