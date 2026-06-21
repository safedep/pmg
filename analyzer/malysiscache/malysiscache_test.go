package malysiscache

import (
	"context"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/localdb"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCache(t *testing.T) *Cache {
	t.Helper()
	mgr := localdb.New(localdb.Config{Dir: t.TempDir(), FileName: "pmg.db"})
	t.Cleanup(func() { require.NoError(t, mgr.Close()) })
	store, err := mgr.Store(context.Background(), Descriptor())
	require.NoError(t, err)
	return New(store, config.MalysisCacheConfig{TTL: 24 * time.Hour})
}

func TestStatsAndClearEmpty(t *testing.T) {
	c := newTestCache(t)
	s, err := c.Stats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, s.Count)
	assert.True(t, s.Oldest.IsZero())

	require.NoError(t, c.Clear(context.Background()))
}

func allow(name, version string) *analyzer.PackageVersionAnalysisResult {
	return &analyzer.PackageVersionAnalysisResult{
		Action:       analyzer.ActionAllow,
		AnalysisID:   "aid-" + version,
		ReferenceURL: "https://ref/" + version,
		Summary:      "clean",
	}
}

func TestSetGetRoundTrip(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()
	p := pkg(packagev1.Ecosystem_ECOSYSTEM_NPM, "left-pad", "1.0.0")

	require.NoError(t, c.Set(ctx, p, allow("left-pad", "1.0.0")))

	got, ok, err := c.Get(ctx, p)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "aid-1.0.0", got.AnalysisID)
	assert.Equal(t, analyzer.ActionAllow, got.Action)
	assert.Equal(t, "left-pad", got.PackageVersion.GetPackage().GetName())
}

func TestSetSkipsWriteWhenTTLNonPositive(t *testing.T) {
	mgr := localdb.New(localdb.Config{Dir: t.TempDir(), FileName: "pmg.db"})
	t.Cleanup(func() { require.NoError(t, mgr.Close()) })
	store, err := mgr.Store(context.Background(), Descriptor())
	require.NoError(t, err)
	c := New(store, config.MalysisCacheConfig{TTL: 0})

	ctx := context.Background()
	p := pkg(packagev1.Ecosystem_ECOSYSTEM_NPM, "left-pad", "1.0.0")
	require.NoError(t, c.Set(ctx, p, allow("left-pad", "1.0.0")))

	s, err := c.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, s.Count, "non-positive TTL disables persistence: nothing written")
}

func TestSetSkipsNonCacheable(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()
	p := pkg(packagev1.Ecosystem_ECOSYSTEM_NPM, "evil", "9.9.9")

	excluded := &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionAllow, IsMalware: true, IsExcluded: true}
	require.NoError(t, c.Set(ctx, p, excluded))

	_, ok, err := c.Get(ctx, p)
	require.NoError(t, err)
	assert.False(t, ok, "excluded-malware must never be cached")
}

func TestGetMissAndExpiry(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()
	p := pkg(packagev1.Ecosystem_ECOSYSTEM_PYPI, "requests", "2.0.0")

	_, ok, err := c.Get(ctx, p)
	require.NoError(t, err)
	assert.False(t, ok)

	require.NoError(t, c.Set(ctx, p, allow("requests", "2.0.0")))

	// Advance the clock past the TTL: the entry is expired and lazily deleted.
	c.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	_, ok, err = c.Get(ctx, p)
	require.NoError(t, err)
	assert.False(t, ok)

	s, err := c.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, s.Count, "expired row should be lazily deleted")
}
