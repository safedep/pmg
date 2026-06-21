package analyzer

import (
	"context"
	"errors"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCache struct {
	getResult *PackageVersionAnalysisResult
	getOK     bool
	getErr    error
	setErr    error
	setCalls  int
}

func (f *fakeCache) Get(context.Context, *packagev1.PackageVersion) (*PackageVersionAnalysisResult, bool, error) {
	return f.getResult, f.getOK, f.getErr
}
func (f *fakeCache) Set(context.Context, *packagev1.PackageVersion, *PackageVersionAnalysisResult) error {
	f.setCalls++
	return f.setErr
}

type fakeAnalyzer struct {
	result    *PackageVersionAnalysisResult
	err       error
	callCount int
}

func (f *fakeAnalyzer) Name() string { return "fake" }
func (f *fakeAnalyzer) Analyze(context.Context, *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {
	f.callCount++
	return f.result, f.err
}

func TestMalysisCachingAnalyzer_Hit(t *testing.T) {
	cached := &PackageVersionAnalysisResult{Action: ActionAllow, AnalysisID: "cached"}
	next := &fakeAnalyzer{}
	a := newMalysisCachingAnalyzer(next, &fakeCache{getResult: cached, getOK: true})

	got, err := a.Analyze(context.Background(), &packagev1.PackageVersion{})
	require.NoError(t, err)
	assert.Equal(t, "cached", got.AnalysisID)
	assert.Equal(t, 0, next.callCount, "hit must not delegate")
}

func TestMalysisCachingAnalyzer_MissDelegatesAndSets(t *testing.T) {
	live := &PackageVersionAnalysisResult{Action: ActionAllow, AnalysisID: "live"}
	next := &fakeAnalyzer{result: live}
	fc := &fakeCache{}
	a := newMalysisCachingAnalyzer(next, fc)

	got, err := a.Analyze(context.Background(), &packagev1.PackageVersion{})
	require.NoError(t, err)
	assert.Equal(t, "live", got.AnalysisID)
	assert.Equal(t, 1, next.callCount)
	assert.Equal(t, 1, fc.setCalls)
}

func TestMalysisCachingAnalyzer_FailSoft(t *testing.T) {
	live := &PackageVersionAnalysisResult{Action: ActionAllow, AnalysisID: "live"}
	next := &fakeAnalyzer{result: live}
	// Get error => treat as miss and delegate; Set error => still return result.
	a := newMalysisCachingAnalyzer(next, &fakeCache{getErr: errors.New("boom"), setErr: errors.New("boom")})

	got, err := a.Analyze(context.Background(), &packagev1.PackageVersion{})
	require.NoError(t, err)
	assert.Equal(t, "live", got.AnalysisID)
	assert.Equal(t, 1, next.callCount)
}

func TestMalysisCachingAnalyzer_AnalyzeErrorNotCached(t *testing.T) {
	next := &fakeAnalyzer{err: errors.New("network")}
	fc := &fakeCache{}
	a := newMalysisCachingAnalyzer(next, fc)

	_, err := a.Analyze(context.Background(), &packagev1.PackageVersion{})
	require.Error(t, err)
	assert.Equal(t, 0, fc.setCalls, "errored analysis must not be cached")
}
