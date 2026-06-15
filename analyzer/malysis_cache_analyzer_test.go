package analyzer

import (
	"context"
	"errors"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAnalyzer struct {
	calls  int
	result *PackageVersionAnalysisResult
	err    error
}

func (f *fakeAnalyzer) Name() string { return "fake" }

func (f *fakeAnalyzer) Analyze(_ context.Context, pkg *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	res := *f.result
	res.PackageVersion = pkg
	return &res, nil
}

type fakeCache struct {
	store  map[string]*PackageVersionAnalysisResult
	getErr error
	setErr error
	setCnt int
	getCnt int
}

func newFakeCache() *fakeCache {
	return &fakeCache{store: map[string]*PackageVersionAnalysisResult{}}
}

func fakeKey(pkg *packagev1.PackageVersion) string {
	return pkg.GetPackage().GetName() + "@" + pkg.GetVersion()
}

func (c *fakeCache) Get(_ context.Context, pkg *packagev1.PackageVersion) (*PackageVersionAnalysisResult, bool, error) {
	c.getCnt++
	if c.getErr != nil {
		return nil, false, c.getErr
	}
	r, ok := c.store[fakeKey(pkg)]
	return r, ok, nil
}

func (c *fakeCache) Set(_ context.Context, pkg *packagev1.PackageVersion, result *PackageVersionAnalysisResult) error {
	c.setCnt++
	if c.setErr != nil {
		return c.setErr
	}
	c.store[fakeKey(pkg)] = result
	return nil
}

func testPkg() *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{Name: "express", Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
		Version: "4.18.0",
	}
}

func TestCacheAnalyzer_AllowVerdictIsCachedAndReused(t *testing.T) {
	inner := &fakeAnalyzer{result: &PackageVersionAnalysisResult{Action: ActionAllow, AnalysisID: "a1"}}
	cache := newFakeCache()
	a := NewMalysisCacheAnalyzer(inner, cache)

	// First call: miss → inner runs → result cached.
	r1, err := a.Analyze(context.Background(), testPkg())
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, r1.Action)
	assert.Equal(t, 1, inner.calls)
	assert.Equal(t, 1, cache.setCnt)

	// Second call: hit → inner not called again.
	r2, err := a.Analyze(context.Background(), testPkg())
	require.NoError(t, err)
	assert.Equal(t, "a1", r2.AnalysisID)
	assert.Equal(t, 1, inner.calls, "inner analyzer must not run on a cache hit")
}

func TestCacheAnalyzer_NonAllowVerdictsAreNotCached(t *testing.T) {
	cases := []struct {
		name   string
		result *PackageVersionAnalysisResult
	}{
		{"block", &PackageVersionAnalysisResult{Action: ActionBlock}},
		{"confirm", &PackageVersionAnalysisResult{Action: ActionConfirm}},
		{"allow but malware", &PackageVersionAnalysisResult{Action: ActionAllow, IsMalware: true}},
		{"allow but excluded", &PackageVersionAnalysisResult{Action: ActionAllow, IsExcluded: true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &fakeAnalyzer{result: tc.result}
			cache := newFakeCache()
			a := NewMalysisCacheAnalyzer(inner, cache)

			_, err := a.Analyze(context.Background(), testPkg())
			require.NoError(t, err)
			assert.Equal(t, 0, cache.setCnt, "non-clean verdict must not be cached")

			// Second call re-runs the inner analyzer (nothing cached).
			_, err = a.Analyze(context.Background(), testPkg())
			require.NoError(t, err)
			assert.Equal(t, 2, inner.calls)
		})
	}
}

func TestCacheAnalyzer_GetErrorFallsBackToInner(t *testing.T) {
	inner := &fakeAnalyzer{result: &PackageVersionAnalysisResult{Action: ActionAllow}}
	cache := newFakeCache()
	cache.getErr = errors.New("boom")
	a := NewMalysisCacheAnalyzer(inner, cache)

	r, err := a.Analyze(context.Background(), testPkg())
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, r.Action)
	assert.Equal(t, 1, inner.calls, "a cache get error must not fail the analysis")
}

func TestCacheAnalyzer_SetErrorDoesNotFailAnalysis(t *testing.T) {
	inner := &fakeAnalyzer{result: &PackageVersionAnalysisResult{Action: ActionAllow}}
	cache := newFakeCache()
	cache.setErr = errors.New("disk full")
	a := NewMalysisCacheAnalyzer(inner, cache)

	r, err := a.Analyze(context.Background(), testPkg())
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, r.Action)
}

func TestCacheAnalyzer_InnerErrorIsPropagated(t *testing.T) {
	inner := &fakeAnalyzer{err: errors.New("analyzer down")}
	cache := newFakeCache()
	a := NewMalysisCacheAnalyzer(inner, cache)

	_, err := a.Analyze(context.Background(), testPkg())
	require.Error(t, err)
	assert.Equal(t, 0, cache.setCnt)
}
